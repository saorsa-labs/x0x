//! KvStore CRDT — a replicated key-value store with access control.
//!
//! Uses OR-Set for key membership (adds win over removes),
//! LWW semantics for values, and HashMap for content storage.
//!
//! ## Access Policies
//!
//! - **Signed**: Only the owner can write. Anyone can read. Incoming deltas
//!   from non-owners are rejected. Use for app stores, agent skill registries.
//! - **Allowlisted**: Only explicitly allowed writers can write. The owner
//!   manages the allowlist. Use for team workspaces, private swarms.
//! - **Encrypted**: group-scoped confidential store (#341). Constructed
//!   only via [`KvStore::new_encrypted`] with an attached secure context;
//!   the v1 write rule is active group membership, and the sync layer seals
//!   every publication (see `kv::encrypted`). A replica carrying the
//!   policy WITHOUT a context — e.g. deserialized legacy state — fails
//!   closed: no authorized writer, no local writes, no delta application.
//! - **AppendOnly**: Like `Signed` (owner-only writes), but existing keys are
//!   immutable — no update, no delete, even by the owner. Use for
//!   tamper-evident event logs where the author must not be able to rewrite
//!   history retroactively.
//! - **SelfKeyed**: No owner. Any agent may join knowing only the topic and
//!   write exclusively under its own namespace: keys whose first 64
//!   characters are the lowercase-hex `AgentId` (an optional `/suffix`
//!   follows). Write authority is bound by the key prefix, not a store owner,
//!   and each agent is capped by a deterministic per-agent quota
//!   ([`MAX_SELFKEYED_KEYS_PER_AGENT`] keys / [`MAX_SELFKEYED_BYTES_PER_AGENT`]
//!   bytes, admitted lowest-N in lexicographic order). Use for open
//!   directories with many mutually-unknown publishers.

use crate::identity::AgentId;
use crate::kv::encrypted::KvSecureContext;
use crate::kv::entry::MergePrior;
use crate::kv::image_admission::{
    now_ms, ImageAdmission, ImageStatus, HARD_IMAGE_LIMIT_BYTES, LOCAL_IMAGE_ALLOWANCE,
    SOFT_IMAGE_LIMIT_BYTES,
};
use crate::kv::{KvEntry, KvError, KvStoreDelta, Result};
use saorsa_gossip_crdt_sync::{DeltaCrdt, LwwRegister, OrSet, OrSetUndo};
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Access control policy for a KvStore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AccessPolicy {
    /// Only the owner can write. Anyone can read and replicate.
    /// Incoming deltas from non-owners are silently rejected.
    Signed,

    /// Only explicitly allowlisted agents can write.
    /// The owner manages the allowlist.
    Allowlisted,

    /// Reserved for group-scoped encrypted stores.
    ///
    /// Phase A (#358) made the variant **unconstructible** through
    /// [`KvStore::new`] ([`KvError::EncryptedPolicyReserved`]) and
    /// **fail-closed** on any replica that carries it without a secure
    /// context. Phase B (#341) wires the real path: [`KvStore::new_encrypted`]
    /// constructs the policy ONLY with an attached
    /// [`KvSecureContext`], and the
    /// v1 write rule becomes **active group membership** — local writes,
    /// remote merges, and checkpoint adoption all consult the context.
    /// Confidentiality is provided by the sync layer: an encrypted store's
    /// gossip publications are sign-then-encrypt sealed records, never
    /// plaintext deltas. A deserialized replica without a re-attached
    /// context remains fail-closed. The bincode discriminant (2) is pinned
    /// on disk and on the wire.
    Encrypted {
        /// MLS group ID for this store.
        group_id: Vec<u8>,
    },

    /// Owner-signed append-only store: like [`Signed`](Self::Signed), only the
    /// owner can write — but existing keys are IMMUTABLE. A key, once written,
    /// can never be updated or deleted, **even by the owner**, and the entry
    /// is frozen in FULL (value, content type, metadata, timestamps).
    /// Re-putting byte-identical content is accepted as an idempotent no-op
    /// (retry-friendly, and it does not advance the checkpoint sequence).
    /// The policy itself is TERMINAL: once a replica knows a store is
    /// append-only, every policy transition away from it is rejected —
    /// announces, checkpoints, and manifests included, regardless of
    /// `policy_version`.
    ///
    /// ## Exact guarantee (read carefully)
    ///
    /// Keys are immutable **after first observation by a
    /// continuously-persistent replica**. A replica that has seen key `k`
    /// (and has not lost its state) rejects every rewrite or removal of `k`
    /// at all enforcement points: local writes, remote deltas — owner-signed
    /// included — and owner-signed checkpoint adoption. A **fresh joiner
    /// with no prior state necessarily trusts the owner's current signed
    /// snapshot**: signatures alone cannot tell it whether that snapshot is
    /// the original history or a rewrite, so two fresh joiners fed different
    /// owner-signed snapshots will adopt divergent states (detectable after
    /// the fact by comparing adopted checkpoint content roots, never
    /// auto-reconciled). Applications that need fresh-joiner rewrite
    /// detection must layer content chaining on top (per-author sequence
    /// numbers + previous-entry hashes, as x0x-symphony's tracker-integrity-v2
    /// does — see saorsa-labs/x0x-symphony#10); witnesses/transparency logs
    /// are out of scope here.
    AppendOnly,

    /// Owner-free open directory: any agent that knows the topic may join,
    /// and each writer owns exactly the keys whose first 64 characters are
    /// the lowercase-hex encoding of its `AgentId` (optionally followed by
    /// `/suffix`). See [`key_agent_prefix`] for the grammar and the binding
    /// invariant (I1: write/tombstone iff `key_agent_prefix(key) ==
    /// Some(writer)`).
    ///
    /// The store has **no owner for its entire life** (`owner = None`;
    /// `OwnerUnknown` never fires) — ownership paths (announces, allowlists,
    /// owner-signed checkpoints) are no-ops. A hard per-agent quota
    /// ([`MAX_SELFKEYED_KEYS_PER_AGENT`] / [`MAX_SELFKEYED_BYTES_PER_AGENT`])
    /// admits writes deterministically (lowest-N lexicographic) so every
    /// replica converges on the same subset. Raising those constants is a
    /// coordinated protocol change; document next to the discriminant pin
    /// (`access_policy_bincode_discriminants_are_pinned`).
    ///
    SelfKeyed,

    /// Public group store with creator-anchored identity and current group
    /// role authorization. Content is plaintext but every mutation is signed.
    /// This variant is appended to preserve every earlier bincode discriminant.
    GroupSigned { group_id: Vec<u8> },

    /// Confidential group store whose records use the live real-TreeKEM
    /// application ratchet. Appended to preserve all existing discriminants.
    TreeKemEncrypted { group_id: Vec<u8> },
}

impl std::fmt::Display for AccessPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signed => write!(f, "signed"),
            Self::Allowlisted => write!(f, "allowlisted"),
            Self::Encrypted { .. } => write!(f, "encrypted"),
            Self::AppendOnly => write!(f, "append_only"),
            Self::SelfKeyed => write!(f, "self_keyed"),
            Self::GroupSigned { .. } => write!(f, "group_signed"),
            Self::TreeKemEncrypted { .. } => write!(f, "treekem_encrypted"),
        }
    }
}

/// Maximum number of active (OR-Set-live) keys one agent may hold in a
/// [`AccessPolicy::SelfKeyed`] store (issue #340).
///
/// Protocol constant, NOT a create-time knob: every joiner must admit the
/// same subset (lowest-N) or replicas split-brain on which keys exist.
/// Raising it is a coordinated protocol change.
pub const MAX_SELFKEYED_KEYS_PER_AGENT: usize = 64;

/// Maximum total value bytes one agent may hold in a
/// [`AccessPolicy::SelfKeyed`] store (issue #340).
///
/// Protocol constant, NOT a create-time knob — see
/// [`MAX_SELFKEYED_KEYS_PER_AGENT`]. Tombstones do not count (they free
/// budget); this is a deterministic admission bound, not spam resistance.
pub const MAX_SELFKEYED_BYTES_PER_AGENT: u64 = 256 * 1024;

/// Parse the writer-binding prefix of a `SelfKeyed` store key (issue #340).
///
/// Grammar: `key := lowercase_hex(AgentId, 64 chars) [ "/" suffix ]`.
///
/// - The first 64 characters must be lowercase hex (`0-9`, `a-f`) decoding to
///   exactly the 32-byte `AgentId`.
/// - If the key is longer than 64 characters, character 65 MUST be `/` — any
///   other separator (`.` `:` `_` …) is rejected, so one agent's namespace is
///   never a prefix of another's.
/// - A bare 64-character key (no suffix) is valid: the agent's root record.
///
/// A key that fails this parse is writable by **no one**.
#[must_use]
pub fn key_agent_prefix(key: &str) -> Option<AgentId> {
    let bytes = key.as_bytes();
    if bytes.len() < 64 {
        return None;
    }
    if bytes.len() > 64 && bytes[64] != b'/' {
        return None;
    }
    let mut id = [0u8; 32];
    for (i, &b) in bytes[..64].iter().enumerate() {
        let v = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            // Uppercase and non-hex characters are rejected.
            _ => return None,
        };
        if i % 2 == 0 {
            id[i / 2] = v << 4;
        } else {
            id[i / 2] |= v;
        }
    }
    Some(AgentId(id))
}

/// Unique identifier for a KvStore (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KvStoreId([u8; 32]);

impl KvStoreId {
    /// Create from raw bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive a store ID from a name and creator.
    #[must_use]
    pub fn from_content(name: &str, creator: &AgentId) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"x0x.store");
        hasher.update(name.as_bytes());
        hasher.update(creator.as_bytes());
        Self(*hasher.finalize().as_bytes())
    }

    /// Derive a store ID that cryptographically binds a `topic` to its
    /// authoritative `owner`.
    ///
    /// Used by BOTH the create and join paths so a creator and an anchored
    /// joiner compute the *same* id — the id is the verifiable topic→owner
    /// binding. A different owner yields a different id, so a rogue cannot
    /// collide with a legitimate store's id by choosing the same topic.
    ///
    /// Uses a distinct domain tag (`x0x.store.v2`) from the legacy
    /// [`from_content`](Self::from_content) (`x0x.store`) so the two
    /// derivations never accidentally agree.
    #[must_use]
    pub fn for_topic_owner(topic: &str, owner: &AgentId) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"x0x.store.v2");
        hasher.update(topic.as_bytes());
        hasher.update(owner.as_bytes());
        Self(*hasher.finalize().as_bytes())
    }

    /// Derive an owner-free store ID for a [`AccessPolicy::SelfKeyed`]
    /// directory topic (issue #340).
    ///
    /// Every joiner who knows only the topic computes the same id — there is
    /// no owner to bind. The domain tag (`x0x.store.selfkeyed.v1`) is
    /// distinct from both `x0x.store` and `x0x.store.v2`, so the same topic
    /// string under `Signed` (via [`for_topic_owner`](Self::for_topic_owner))
    /// never collides with its self-keyed directory.
    #[must_use]
    pub fn for_self_keyed_topic(topic: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"x0x.store.selfkeyed.v1");
        hasher.update(topic.as_bytes());
        Self(*hasher.finalize().as_bytes())
    }
}

impl std::fmt::Display for KvStoreId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

fn default_seq_counter() -> Arc<AtomicU64> {
    Arc::new(AtomicU64::new(0))
}

/// The authenticated channel through which a store's owner was anchored.
///
/// Pure audit metadata: the security property is the anchored `owner` itself
/// (set at construction), not which channel supplied it. Recording the channel
/// makes a misconfigured or unauthenticated anchor source visible rather than
/// silent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnchorChannel {
    /// This node created the store (`owner = self`).
    Creator,
    /// Owner supplied via a REST/CLI `expected_owner` parameter (the local
    /// user/operator is the trust root).
    RestParam,
    /// Owner replayed from the persisted manifest after a restart. Stores
    /// deserialized from a pre-ownership-source format use this honest label.
    #[default]
    Persistence,
}

/// How a store's ownership was established — surfaced on reads for
/// auditability. See the module-level "Access Policies" docs and
/// [`KvStore::learn_ownership`] for the construction-only ownership invariant.
///
/// This is a *derived view* of the authoritative `owner` field plus the last
/// observed conflict, not an independent source of truth: writes are gated on
/// `owner`/`policy`, never on this enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnershipSource {
    /// Owner supplied out-of-band at construction. This is the only state
    /// that permits writes; it converges against any owner version (v0.30.1
    /// included) because no announce is consulted on the data path.
    Anchored {
        /// The anchored owner.
        owner: AgentId,
        /// How the owner was supplied.
        channel: AnchorChannel,
    },
    /// No owner anchored. Fail-closed read-only by design — writes return
    /// [`KvError::OwnerUnknown`]. The protocol refuses to derive ownership
    /// from the network, so this is permanent, not a pending state.
    Unknown,
    /// The anchored owner disagrees with a received announce. The store stays
    /// on the anchored owner (writes by it still work); the conflict is
    /// surfaced so a takeover attempt or misconfiguration is visible.
    Conflict {
        /// The anchored (construction-time) owner.
        anchored: AgentId,
        /// The owner claimed by the rejected announce.
        announced: AgentId,
    },
}

/// Wire-friendly ownership discriminant for REST/audit surfaces.
///
/// Unlike [`OwnershipSource`] (which carries `AgentId` detail for in-process
/// audit), this carries only the status tag; the owner/announced identities
/// travel as hex strings alongside it in DTOs. Strongly typed (not a string)
/// per the ownership-source design decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipStatus {
    /// Owner anchored at construction; writes permitted for the owner.
    Anchored,
    /// No owner anchored — permanently read-only by design.
    Unknown,
    /// Anchored owner disagrees with a received announce; owner unchanged.
    Conflict,
}

/// Domain-separation tag for owner-checkpoint signatures.
const CHECKPOINT_SIG_DOMAIN: &[u8] = b"x0x.store.checkpoint.sig.v1";
/// Domain-separation tag for content-root hashing.
const CHECKPOINT_ROOT_DOMAIN: &[u8] = b"x0x.store.checkpoint.root.v2";

/// Domain-separation tag for served-state digest hashing (issue #240).
const SERVED_DIGEST_DOMAIN: &[u8] = b"x0x.store.served.digest.v1";

/// Owner-signed content provenance for a store snapshot.
///
/// Decouples "who relays" from "who authored": the signature is content-level
/// (the owner's ML-DSA-65 key), so a re-wrapping replica cannot strip it. This
/// lets an anchored joiner cold-recover a Signed store from a non-owner
/// replica while the owner is offline — the replica relays
/// `(checkpoint + entries)` and the joiner verifies the owner's signature and
/// recomputes the content root, independent of the relayer.
///
/// **Never establishes ownership.** A checkpoint can only be adopted by a
/// replica already anchored on `expected_owner`; it proves data provenance,
/// not ownership. An unanchored replica rejects all checkpoints (fail-closed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerCheckpoint {
    /// Store topic this checkpoint binds (cross-topic replay defense).
    pub topic: String,
    /// Store id (must equal `for_topic_owner(topic, owner)`).
    pub store_id: KvStoreId,
    /// Owner's ML-DSA-65 public key bytes (self-proving).
    pub owner_pubkey: Vec<u8>,
    /// Policy at checkpoint time.
    pub policy: AccessPolicy,
    /// Policy freshness counter at checkpoint time.
    pub policy_version: u64,
    /// Monotonic checkpoint sequence (owner-incremented). Replay/downgrade gate.
    pub checkpoint_seq: u64,
    /// Canonical BLAKE3 root over every security-relevant field of the active
    /// entry set — see [`content_root`].
    pub content_root: [u8; 32],
    /// Unix ms (skew/freshness logging only; `checkpoint_seq` is authoritative).
    pub timestamp: u64,
    /// ML-DSA-65 signature over [`signing_bytes`](Self::signing_bytes).
    pub signature: Vec<u8>,
}

impl OwnerCheckpoint {
    /// The forgeable bytes covered by the signature (everything except the
    /// signature itself).
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(CHECKPOINT_SIG_DOMAIN);
        buf.extend_from_slice(self.topic.as_bytes());
        buf.extend_from_slice(self.store_id.as_bytes());
        buf.extend_from_slice(&self.owner_pubkey);
        // Policy is bincode-encoded so nested variants are unambiguous.
        buf.extend_from_slice(&bincode::serialize(&self.policy).unwrap_or_default());
        buf.extend_from_slice(&self.policy_version.to_le_bytes());
        buf.extend_from_slice(&self.checkpoint_seq.to_le_bytes());
        buf.extend_from_slice(&self.content_root);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf
    }

    /// Verify owner binding, store binding, and signature against the anchored
    /// `expected_owner`.
    ///
    /// # Errors
    ///
    /// Returns [`KvError::OwnerTokenInvalid`] if the public key does not parse,
    /// does not derive to `expected_owner`, or the signature is invalid.
    pub fn verify(&self, expected_owner: &AgentId) -> Result<()> {
        use ant_quic::crypto::raw_public_keys::pqc::{verify_with_ml_dsa, MlDsaSignature};
        let pubkey = ant_quic::MlDsaPublicKey::from_bytes(&self.owner_pubkey)
            .map_err(|e| KvError::OwnerTokenInvalid(format!("bad owner pubkey: {e:?}")))?;
        // Owner binding: the pubkey must derive to the anchored owner.
        let derived = AgentId::from_public_key(&pubkey);
        if &derived != expected_owner {
            return Err(KvError::OwnerTokenInvalid(
                "checkpoint owner_pubkey does not derive to the anchored owner".to_string(),
            ));
        }
        let sig = MlDsaSignature::from_bytes(&self.signature)
            .map_err(|e| KvError::OwnerTokenInvalid(format!("bad signature: {e:?}")))?;
        verify_with_ml_dsa(&pubkey, &self.signing_bytes(), &sig).map_err(|e| {
            KvError::OwnerTokenInvalid(format!("invalid checkpoint signature: {e:?}"))
        })?;
        Ok(())
    }
}

/// Deterministic canonical BLAKE3 root over the store name and active entry
/// set.
///
/// Computable identically by the owner (at checkpoint time) and a receiver
/// (from a relay), so a relayer cannot tamper with the store name or any
/// entry field without breaking the root. Each entry is encoded canonically
/// with length-delimited fields covering the outer map key and **every**
/// security-relevant field (inner key, value, content_hash, content_type,
/// metadata, timestamps). The store name is length-delimited and hashed
/// before the entries. Entries are sorted by outer key for determinism.
#[must_use]
pub fn content_root(store_id: &KvStoreId, name: &str, entries: &[(&str, &KvEntry)]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(CHECKPOINT_ROOT_DOMAIN);
    h.update(store_id.as_bytes());
    // Store name: length-delimited so it cannot collide with entry data.
    h.update(&(name.len() as u64).to_le_bytes());
    h.update(name.as_bytes());
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (outer_key, entry) in &sorted {
        h.update(&entry_commitment_bytes(outer_key, entry));
    }
    *h.finalize().as_bytes()
}

/// Canonical length-delimited encoding of a single entry's security-relevant
/// fields for checkpoint commitment.
///
/// Every variable-length field is prefixed with its byte length as a 64-bit
/// little-endian integer so the encoding is unambiguous (no field-boundary
/// collisions). The outer map key is included alongside the entry's inner key
/// so a relay cannot swap an entry between map slots.
fn entry_commitment_bytes(outer_key: &str, entry: &KvEntry) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    lp_bytes(&mut buf, outer_key.as_bytes());
    lp_bytes(&mut buf, entry.key.as_bytes());
    lp_bytes(&mut buf, &entry.value);
    lp_bytes(&mut buf, &entry.content_hash);
    lp_bytes(&mut buf, entry.content_type.as_bytes());
    // Metadata: canonicalize by sorting key-value pairs.
    let mut meta: Vec<_> = entry.metadata.iter().collect();
    meta.sort_by(|a, b| a.0.cmp(b.0));
    buf.extend_from_slice(&(meta.len() as u64).to_le_bytes());
    for (mk, mv) in &meta {
        lp_bytes(&mut buf, mk.as_bytes());
        lp_bytes(&mut buf, mv.as_bytes());
    }
    buf.extend_from_slice(&entry.created_at.to_le_bytes());
    buf.extend_from_slice(&entry.updated_at.to_le_bytes());
    buf
}

/// Write a length-prefixed byte slice (64-bit LE length + data).
pub(super) fn lp_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
    buf.extend_from_slice(data);
}

/// Deterministic canonical BLAKE3 digest over the active entry set alone.
///
/// This is the content commitment carried by `StateServedV2` markers (issue
/// #240): a serving holder declares it, and a bootstrapping requester
/// recomputes it over its OWN state, stopping only when they match. Unlike
/// [`content_root`] it deliberately EXCLUDES the store name — a fresh joiner
/// constructs its replica with a placeholder name, so a name-binding digest
/// could never match (and the name is LWW metadata, not entry history; it
/// rides every delta anyway). The store id binds the digest to one logical
/// store, so a marker replayed onto another store's side topic can never
/// verify. Entries are sorted by outer key and committed with the same
/// canonical encoding as [`content_root`], so holder and requester agree
/// byte-for-byte on identical content. The empty set's digest is universally
/// computable — that is what lets an EMPTY holder declare authoritative
/// emptiness to an empty requester.
///
/// Unlike [`content_root`] it also EXCLUDES `created_at` (F1, fix-loop):
/// [`KvEntry::merge`] preserves the EARLIEST `created_at`, so when an owner
/// deletes and re-creates a key, a replica holding the original entry keeps
/// `T1` while the owner commits `T2` — a digest committing `created_at`
/// would NEVER match and the bootstrap would wedge at capped cadence
/// forever. `created_at` is display provenance, not merge-converged content
/// (`updated_at` IS merge-stable: max-wins, so both sides agree on it after
/// the serve merges). The checkpoint `content_root` keeps `created_at`
/// because checkpoint adoption is a full REPLACE verified byte-for-byte —
/// no merge semantics, so the commitment there is exact.
#[must_use]
pub(crate) fn served_content_digest(
    store_id: &KvStoreId,
    entries: &[(&str, &KvEntry)],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(SERVED_DIGEST_DOMAIN);
    h.update(store_id.as_bytes());
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (outer_key, entry) in &sorted {
        h.update(&served_entry_commitment_bytes(outer_key, entry));
    }
    *h.finalize().as_bytes()
}

/// Canonical length-delimited encoding of one entry's merge-converged
/// fields for the served-state digest. Identical to
/// [`entry_commitment_bytes`] MINUS `created_at` — see
/// [`served_content_digest`] for why.
fn served_entry_commitment_bytes(outer_key: &str, entry: &KvEntry) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    lp_bytes(&mut buf, outer_key.as_bytes());
    lp_bytes(&mut buf, entry.key.as_bytes());
    lp_bytes(&mut buf, &entry.value);
    lp_bytes(&mut buf, &entry.content_hash);
    lp_bytes(&mut buf, entry.content_type.as_bytes());
    let mut meta: Vec<_> = entry.metadata.iter().collect();
    meta.sort_by(|a, b| a.0.cmp(b.0));
    buf.extend_from_slice(&(meta.len() as u64).to_le_bytes());
    for (mk, mv) in &meta {
        lp_bytes(&mut buf, mk.as_bytes());
        lp_bytes(&mut buf, mv.as_bytes());
    }
    buf.extend_from_slice(&entry.updated_at.to_le_bytes());
    buf
}

/// Full-field entry equality for the AppendOnly freeze.
///
/// Under [`AccessPolicy::AppendOnly`] an existing entry is frozen in FULL —
/// value, content hash, content type, metadata, and both timestamps — not
/// just its value bytes. This matches exactly the fields the owner-signed
/// checkpoint root commits to (see [`entry_commitment_bytes`]), so "equal
/// here" and "same commitment" are the same statement.
fn entry_frozen_fields_equal(a: &KvEntry, b: &KvEntry) -> bool {
    a.key == b.key
        && a.value == b.value
        && a.content_hash == b.content_hash
        && a.content_type == b.content_type
        && a.metadata == b.metadata
        && a.created_at == b.created_at
        && a.updated_at == b.updated_at
}

/// Validate that a relayed entry is internally consistent before adoption.
///
/// Independently enforces:
/// - `outer_key == entry.key` (the entry has not been moved between map slots)
/// - `content_hash == blake3(value)` (the value matches its claimed hash)
///
/// Called before any mutation or high-water update caused by checkpoint
/// adoption. Failures reject the entire checkpoint adoption (fail-closed).
fn validate_entry_integrity(outer_key: &str, entry: &KvEntry) -> Result<()> {
    if outer_key != entry.key {
        return Err(KvError::Merge(format!(
            "checkpoint entry outer key {outer_key:?} != inner key {:?}",
            entry.key
        )));
    }
    let computed = *blake3::hash(&entry.value).as_bytes();
    if computed != entry.content_hash {
        return Err(KvError::Merge(
            "checkpoint entry content_hash != blake3(value)".to_string(),
        ));
    }
    Ok(())
}

/// What a merge changed in a store's entries, so that it can be undone
/// without copying the store first (#1970).
#[derive(Default)]
struct EntryJournal {
    /// The first prior state of each changed key.
    priors: HashMap<String, EntryPrior>,
}

enum EntryPrior {
    Absent,
    Entry(KvEntry),
    CreatedAt(u64),
}

impl EntryJournal {
    fn record(&mut self, key: &str, prior: EntryPrior) {
        match self.priors.get_mut(key) {
            None => {
                self.priors.insert(key.to_string(), prior);
            }
            Some(existing) => {
                // Only `created_at` had moved; the replaced entry carries
                // the moved value, so restore the first one into it.
                if let EntryPrior::CreatedAt(first) = existing {
                    let first = *first;
                    if let EntryPrior::Entry(mut entry) = prior {
                        entry.created_at = first;
                        *existing = EntryPrior::Entry(entry);
                    }
                }
            }
        }
    }
}

/// Inputs required to build an owner-signed checkpoint.
pub struct OwnerCheckpointParams<'a> {
    pub topic: &'a str,
    pub store_id: &'a KvStoreId,
    pub secret_key: &'a ant_quic::MlDsaSecretKey,
    pub public_key: &'a ant_quic::MlDsaPublicKey,
    pub policy: &'a AccessPolicy,
    pub policy_version: u64,
    pub checkpoint_seq: u64,
    pub content_root: [u8; 32],
    pub timestamp: u64,
}

/// Build and sign an [`OwnerCheckpoint`] with the owner's key.
///
/// This is the production side (owner only). Replicas never call this — they
/// only cache and relay checkpoints produced by the owner.
///
/// # Errors
///
/// Returns [`KvError::Gossip`] if checkpoint signing fails.
pub fn make_owner_checkpoint(params: OwnerCheckpointParams<'_>) -> Result<OwnerCheckpoint> {
    use ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa;
    let owner_pubkey = params.public_key.as_bytes().to_vec();
    let cp = OwnerCheckpoint {
        topic: params.topic.to_string(),
        store_id: *params.store_id,
        owner_pubkey,
        policy: params.policy.clone(),
        policy_version: params.policy_version,
        checkpoint_seq: params.checkpoint_seq,
        content_root: params.content_root,
        timestamp: params.timestamp,
        signature: Vec::new(),
    };
    let bytes = cp.signing_bytes();
    let sig = sign_with_ml_dsa(params.secret_key, &bytes)
        .map_err(|e| KvError::Gossip(format!("owner checkpoint sign failed: {e:?}")))?;
    let mut cp = cp;
    cp.signature = sig.as_bytes().to_vec();
    Ok(cp)
}

/// Internal merge disposition: a successful public call may deliberately ignore
/// stale or unauthorized input. Callers must not treat that as mutation authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MergeOutcome {
    Applied,
    SubsumedCheckpoint,
    Rejected(MergeRejection),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MergeRejection {
    GroupSignedAuthority,
    UnauthorizedWriter,
    AnonymousWriter,
    AmbiguousDelta,
    /// #1094 P1/P2: an entry under another key than its own, or whose
    /// content hash is not the hash of its value.
    InconsistentEntry,
}

/// Encoded bytes of one OR-Set tag: a peer id and a sequence number.
const ORSET_TAG_BYTES: u64 = 40;

#[cfg(test)]
thread_local! {
    /// Whole-store content measures on this thread (#2110 tests).
    pub(crate) static FULL_MEASURES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Rollback snapshots that copy the whole OR-Set, taken on this thread
    /// (#2110 tests). The bounded delta path takes none (#2146).
    pub(crate) static SNAPSHOTS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// OR-Set elements saved in delta undo logs on this thread (#2146
    /// tests): one per touched key of each delta that took the undo path.
    pub(crate) static DELTA_UNDO_SAVES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// What [`KvStore::rollback`] puts back besides the journaled entries.
enum Rollback {
    /// The store without its entries; the OR-Set is a whole copy.
    Copy(Box<KvStore>),
    /// The store without its entries and without its OR-Set, and an undo
    /// log for the OR-Set elements the merge may touch (#2146).
    Undo(Box<KvStore>, OrSetUndo<String>),
}

/// Encoded bytes of a writer mark (#1094 P1): agent id, signature, version
/// tag and their names, with length prefixes, rider label at its bound. The
/// test `writer_mark_bytes_bound_the_mark` checks it.
pub(crate) const WRITER_MARK_BYTES: usize = 4_800;

/// Encoded bytes of an entry besides its key (twice: map key and inner
/// key), value and content type: lengths, hash, metadata count, times.
const ENTRY_FIXED_BYTES: usize = 128;

/// Encoded bytes of one OR-Set tag for a key, besides the key.
const KEY_TAG_BYTES: usize = 128;

/// Whether any entry of `delta` fails [`validate_entry_integrity`]: it sits
/// under a map key other than its own, or its content hash is not the hash
/// of its value (#1094 P1/P2, reviews of #1963).
fn delta_has_inconsistent_entry(delta: &KvStoreDelta) -> bool {
    delta
        .added
        .iter()
        .any(|(key, (entry, _))| validate_entry_integrity(key, entry).is_err())
        || delta
            .updated
            .iter()
            .any(|(key, entry)| validate_entry_integrity(key, entry).is_err())
}

/// A replicated key-value store using CRDTs with access control.
///
/// Combines:
/// - OR-Set for key membership (which keys exist)
/// - HashMap for entry content (the KvEntry values)
/// - LWW-Register for store metadata (name)
/// - Access control via owner, allowlist, and policy
#[derive(Clone, Serialize, Deserialize)]
pub struct KvStore {
    /// Unique identifier for this store.
    id: KvStoreId,

    /// Key membership — OR-Set ensures adds win over removes.
    keys: OrSet<String>,

    /// Key-value entries indexed by key name.
    entries: HashMap<String, KvEntry>,

    /// Store name (LWW semantics).
    name: LwwRegister<String>,

    /// Access control policy.
    #[serde(default = "default_policy")]
    policy: AccessPolicy,

    /// Store owner (the agent that created it).
    ///
    /// Ownership is established ONLY at construction — either by the creator
    /// ([`new`](Self::new)) or from trusted out-of-band input at join
    /// ([`new_replica`](Self::new_replica)). It is **never** adopted from an
    /// untrusted network announce (see [`learn_ownership`](Self::learn_ownership)).
    /// For Signed and Allowlisted policies, only the owner (and allowlisted
    /// writers) can write.
    #[serde(default)]
    owner: Option<AgentId>,

    /// Agents allowed to write (for Allowlisted policy).
    /// The owner is implicitly allowed and does not need to be in this set.
    #[serde(default)]
    allowed_writers: HashSet<AgentId>,

    /// Version counter — incremented on every mutation.
    #[serde(default)]
    version: u64,

    // ---------------------------------------------------------------------
    // TRAILING FIELDS — added after the original `KvStore` shape.
    //
    // bincode (wire + disk format) is positional and non-self-describing.
    // Plain `#[serde(default)]` does NOT tolerate a missing field there:
    // bincode returns an EOF *error* (not `Ok(None)`) at stream end, so serde
    // never applies the default. Every field below is therefore (a) declared
    // LAST, after the original `id..version` shape, and (b) decoded with
    // `de_tolerant`, a custom deserializer that catches EOF/short streams and
    // yields the field's `Default`. This lets a blob written by the original
    // (pre-ownership, pre-checkpoint) `KvStore` shape — whose bytes END at
    // `version` — deserialize with these fields defaulted instead of failing.
    //
    // INVARIANT: any NEW persisted field MUST be appended at the end of this
    // block with the same `de_tolerant` treatment. Never insert a persisted
    // field mid-struct, or older blobs will misalign and fail to decode.
    // ---------------------------------------------------------------------
    /// Latest owner-signed checkpoint this replica has merged or produced.
    /// Persisted so owner restarts never regress the checkpoint sequence; a
    /// blob written before this field existed decodes to `None`.
    #[serde(default, deserialize_with = "de_tolerant")]
    pub(crate) latest_checkpoint: Option<OwnerCheckpoint>,

    /// Highest `checkpoint_seq` adopted (replay/downgrade high-water mark).
    /// Persisted so owner restarts never regress the checkpoint sequence.
    #[serde(default, deserialize_with = "de_tolerant")]
    pub(crate) highest_checkpoint_seq: u64,

    /// How the owner was anchored (audit metadata); meaningful only when
    /// `owner` is `Some`.
    #[serde(default, deserialize_with = "de_tolerant")]
    anchor_channel: AnchorChannel,

    /// Monotonic freshness counter for owner-announced policy refreshes.
    ///
    /// A policy refresh from [`learn_ownership`](Self::learn_ownership) is
    /// applied only when the announce carries a strictly greater
    /// `policy_version`, which blocks a replayed authentic-but-stale announce
    /// from downgrading policy. This is owner-local metadata; it is NOT a
    /// CRDT-merged value.
    #[serde(default, deserialize_with = "de_tolerant")]
    policy_version: u64,

    /// The last announce whose claimed owner conflicted with the anchored
    /// owner (audit only). Cleared when the anchored owner itself refreshes
    /// via a matching forward-version announce. `None` when no conflict has
    /// been observed (or it has been cleared).
    #[serde(default, deserialize_with = "de_tolerant")]
    ownership_conflict: Option<(AgentId, AgentId)>,

    /// Current writer who most recently authenticated and endorsed a retained
    /// public-group history image. This is local import provenance; a remote
    /// image's copy is never adopted.
    #[serde(default, deserialize_with = "de_tolerant")]
    last_history_endorser: Option<AgentId>,

    /// Monotonic sequence counter for unique OR-Set tags.
    #[serde(skip, default = "default_seq_counter")]
    seq_counter: Arc<AtomicU64>,

    // ---------------------------------------------------------------------
    // NOT-persisted extension (#341 Phase B): the secure context backing an
    // [`AccessPolicy::Encrypted`] store. `serde(skip)` keeps the bincode
    // wire/disk layout unchanged — a deserialized store carries `None` and
    // stays fail-closed until a caller re-attaches a context via
    // [`KvStore::set_secure_context`]. Never insert a PERSISTED field after
    // `seq_counter` without the `de_tolerant` treatment (see above).
    // ---------------------------------------------------------------------
    /// Group secure context for `Encrypted` stores. `None` on every other
    /// policy, and on `Encrypted` replicas restored from a snapshot until
    /// re-attached — which is exactly the Phase A fail-closed state.
    #[serde(skip, default)]
    secure: Option<std::sync::Arc<dyn KvSecureContext>>,

    /// #1970: retained-image admission state; not persisted.
    #[serde(skip, default)]
    image: ImageAdmission,

    /// #2110: the last [`Self::orset_digest`]; not persisted.
    #[serde(skip, default)]
    orset_digest_cache: OrsetDigestCache,
}

impl std::fmt::Debug for KvStore {
    /// Manual impl because `Arc<dyn KvSecureContext>` is not `Debug`; the
    /// context is summarized by presence only (never its contents).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvStore")
            .field("id", &self.id)
            .field("name_register", &self.name)
            .field("policy", &self.policy)
            .field("owner", &self.owner)
            .field("allowed_writers", &self.allowed_writers)
            .field("version", &self.version)
            .field("entry_count", &self.entries.len())
            .field("anchor_channel", &self.anchor_channel)
            .field("policy_version", &self.policy_version)
            .field("ownership_conflict", &self.ownership_conflict)
            .field("last_history_endorser", &self.last_history_endorser)
            .field("latest_checkpoint", &self.latest_checkpoint)
            .field("highest_checkpoint_seq", &self.highest_checkpoint_seq)
            .field("secure_context_attached", &self.secure.is_some())
            .finish_non_exhaustive()
    }
}

/// The last OR-Set digest with the `(version, keys.version())` it was
/// computed at. Every path that changes the OR-Set moves the store version.
#[derive(Debug, Default)]
struct OrsetDigestCache(std::sync::Mutex<Option<(u64, u64, [u8; 32])>>);

impl Clone for OrsetDigestCache {
    fn clone(&self) -> Self {
        Self(std::sync::Mutex::new(
            *self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        ))
    }
}

/// Deserialize a trailing, defaultable `KvStore` field, tolerating its absence.
///
/// bincode is positional and non-self-describing: a blob written by an older
/// `KvStore` shape simply ends before these trailing fields, so bincode hits
/// EOF when asked to read them. Decoding the value if present, or falling back
/// to `T::default()` on EOF / any malformed tail, makes such a blob load with
/// the newer fields defaulted rather than failing outright. Only sound at
/// stream-EOF for genuinely trailing fields (see the struct's TRAILING note).
pub(crate) fn de_tolerant<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de> + Default,
{
    Ok(T::deserialize(deserializer).unwrap_or_default())
}

/// The exact serde shape of [`KvStore`] as persisted inside **v1** snapshot
/// files (`X0XKVS1\0`), i.e. by every release up to and including v0.45.0.
///
/// FROZEN — never edit. Field order and serde attributes mirror
/// `git show v0.45.0:src/kv/store.rs` byte-for-byte in encoding terms. A v1
/// snapshot body is `bincode(store) || u64 seq_counter`, so the store is NOT
/// at stream end: any field appended to [`KvStore`] after v0.45.0 (e.g.
/// `last_history_endorser`) would consume the leading bytes of `seq_counter`
/// and fail every v0.45.0 file. v1 files are therefore decoded through this
/// frozen shape and converted with [`KvStore::from_v1_snapshot_shape`];
/// fields added since v0.45.0 take their defaults.
#[derive(Deserialize)]
pub(crate) struct KvStoreV1SnapshotShape {
    id: KvStoreId,
    keys: OrSet<String>,
    entries: HashMap<String, KvEntry>,
    name: LwwRegister<String>,
    #[serde(default = "default_policy")]
    policy: AccessPolicy,
    #[serde(default)]
    owner: Option<AgentId>,
    #[serde(default)]
    allowed_writers: HashSet<AgentId>,
    #[serde(default)]
    version: u64,
    #[serde(default, deserialize_with = "de_tolerant")]
    latest_checkpoint: Option<OwnerCheckpoint>,
    #[serde(default, deserialize_with = "de_tolerant")]
    highest_checkpoint_seq: u64,
    #[serde(default, deserialize_with = "de_tolerant")]
    anchor_channel: AnchorChannel,
    #[serde(default, deserialize_with = "de_tolerant")]
    policy_version: u64,
    #[serde(default, deserialize_with = "de_tolerant")]
    ownership_conflict: Option<(AgentId, AgentId)>,
}

fn default_policy() -> AccessPolicy {
    AccessPolicy::Signed
}

/// What an ownership announce would do to a store — see
/// [`KvStore::check_ownership_announce`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnershipAnnounceEffect {
    /// A different owner is anchored: the conflict gets recorded (mutation).
    Conflict {
        /// The anchored owner.
        anchored: AgentId,
    },
    /// Owner matches and the policy version is current or newer (mutation).
    Refresh,
    /// Owner matches but the policy version is older: nothing changes.
    Stale,
}

impl KvStore {
    /// Create a new empty KvStore with the given access policy.
    /// Create a new empty KvStore owned by `owner` with the given access
    /// policy.
    ///
    /// This is the **creator** path: ownership is anchored on `owner` at
    /// construction (channel [`AnchorChannel::Creator`]) and is immutable for
    /// the life of the store.
    ///
    /// # Errors
    ///
    /// [`KvError::EncryptedPolicyReserved`] if `policy` is
    /// [`AccessPolicy::Encrypted`]: this constructor accepts no secure
    /// context, so an Encrypted store built here could not honor its policy.
    /// The name must not over-promise — use
    /// [`new_encrypted`](Self::new_encrypted) with a live
    /// [`KvSecureContext`]; a replica
    /// that carries the policy without a context fails closed.
    pub fn new(id: KvStoreId, name: String, owner: AgentId, policy: AccessPolicy) -> Result<Self> {
        if let AccessPolicy::Encrypted { group_id } | AccessPolicy::TreeKemEncrypted { group_id } =
            &policy
        {
            tracing::warn!(
                target: "x0x::kv",
                "refused to construct store {} with reserved encrypted policy (group_id {}) — use KvStore::new_encrypted with an attached secure context",
                id,
                hex::encode(group_id)
            );
            return Err(KvError::EncryptedPolicyReserved {
                group_id: group_id.clone(),
            });
        }
        let mut name_reg = LwwRegister::new(name.clone());
        // Stamp the creator-set name with a non-empty clock so it wins LWW
        // merge against replicas initialized with empty names and empty
        // clocks (which would otherwise be concurrent and hash-tiebroken).
        name_reg.set(name, PeerId::new(owner.0));
        Ok(Self {
            id,
            keys: OrSet::new(),
            entries: HashMap::new(),
            name: name_reg,
            policy,
            owner: Some(owner),
            anchor_channel: AnchorChannel::Creator,
            policy_version: 0,
            ownership_conflict: None,
            last_history_endorser: None,
            latest_checkpoint: None,
            highest_checkpoint_seq: 0,
            allowed_writers: HashSet::new(),
            version: 0,
            seq_counter: Arc::new(AtomicU64::new(0)),
            secure: None,
            image: ImageAdmission::default(),
            orset_digest_cache: OrsetDigestCache::default(),
        })
    }

    /// Create a new empty group-scoped encrypted store (#341 Phase B).
    ///
    /// This is the ONLY production path that constructs
    /// [`AccessPolicy::Encrypted`]: the caller must supply a live
    /// [`KvSecureContext`] bound to the same `group_id`, so every
    /// authorization decision on this store (local writes, remote merges,
    /// checkpoint adoption) consults real group membership and every
    /// publication is sealed by the sync layer. A store created here without
    /// a running encrypted sync is inert (writes still refuse), never
    /// plaintext-gossiping.
    ///
    /// The plain [`new`](Self::new) keeps rejecting `Encrypted` — a caller
    /// without a context has no way to honor the policy, so the name must
    /// not construct.
    ///
    /// # Errors
    ///
    /// [`KvError::Unauthorized`] if `ctx` is bound to a different group than
    /// `group_id` (mis-wired construction).
    pub fn new_encrypted(
        id: KvStoreId,
        name: String,
        owner: AgentId,
        group_id: Vec<u8>,
        ctx: Arc<dyn KvSecureContext>,
    ) -> Result<Self> {
        if ctx.group_id() != group_id {
            return Err(KvError::Unauthorized(format!(
                "secure context is bound to group {} but the store requests group {}",
                hex::encode(ctx.group_id()),
                hex::encode(&group_id)
            )));
        }
        let mut name_reg = LwwRegister::new(name.clone());
        // Stamp the creator-set name with a non-empty clock so it wins LWW
        // merge against replicas initialized with empty names (see `new`).
        name_reg.set(name, PeerId::new(owner.0));
        Ok(Self {
            id,
            keys: OrSet::new(),
            entries: HashMap::new(),
            name: name_reg,
            policy: AccessPolicy::Encrypted { group_id },
            owner: Some(owner),
            anchor_channel: AnchorChannel::Creator,
            policy_version: 0,
            ownership_conflict: None,
            last_history_endorser: None,
            latest_checkpoint: None,
            highest_checkpoint_seq: 0,
            allowed_writers: HashSet::new(),
            version: 0,
            seq_counter: Arc::new(AtomicU64::new(0)),
            secure: Some(ctx),
            image: ImageAdmission::default(),
            orset_digest_cache: OrsetDigestCache::default(),
        })
    }

    /// Create a real-TreeKEM protected store with a synchronous authorization
    /// view. Wire encryption is supplied separately to `KvStoreSync`.
    pub fn new_treekem_encrypted(
        id: KvStoreId,
        name: String,
        owner: AgentId,
        group_id: Vec<u8>,
        ctx: Arc<dyn KvSecureContext>,
    ) -> Result<Self> {
        let mut store = Self::new_encrypted(id, name, owner, group_id.clone(), ctx)?;
        store.policy = AccessPolicy::TreeKemEncrypted { group_id };
        Ok(store)
    }

    /// Create a public group-signed store with an attached current-policy context.
    pub fn new_group_signed(
        id: KvStoreId,
        name: String,
        owner: AgentId,
        group_id: Vec<u8>,
        ctx: Arc<dyn KvSecureContext>,
    ) -> Result<Self> {
        if ctx.group_id() != group_id {
            return Err(KvError::Unauthorized(
                "group context binding mismatch".to_string(),
            ));
        }
        let mut store = Self::new(id, name, owner, AccessPolicy::Signed)?;
        store.policy = AccessPolicy::GroupSigned { group_id };
        store.secure = Some(ctx);
        Ok(store)
    }

    /// Attach (or replace) the secure context on an `Encrypted` replica.
    ///
    /// This is the snapshot-restore / rehydration path: a deserialized store
    /// carries no context (the field is `serde(skip)`) and is fail-closed
    /// until the caller re-binds one. Rejects a context bound to a different
    /// group and a context-less call on a non-encrypted store (a no-op
    /// attachment there would be silently meaningless).
    ///
    /// # Errors
    ///
    /// [`KvError::EncryptedPolicyReserved`] if the store is not
    /// `Encrypted`; [`KvError::Unauthorized`] on a group binding mismatch.
    pub fn set_secure_context(&mut self, ctx: Arc<dyn KvSecureContext>) -> Result<()> {
        let group_id = match &self.policy {
            AccessPolicy::Encrypted { group_id }
            | AccessPolicy::GroupSigned { group_id }
            | AccessPolicy::TreeKemEncrypted { group_id } => group_id,
            _ => {
                return Err(KvError::EncryptedPolicyReserved {
                    group_id: Vec::new(),
                });
            }
        };
        if ctx.group_id() != *group_id {
            return Err(KvError::Unauthorized(format!(
                "secure context is bound to group {} but the store is bound to group {}",
                hex::encode(ctx.group_id()),
                hex::encode(group_id)
            )));
        }
        self.secure = Some(ctx);
        Ok(())
    }

    /// The attached secure context, if any (encrypted stores only).
    #[must_use]
    pub fn secure_context(&self) -> Option<&Arc<dyn KvSecureContext>> {
        self.secure.as_ref()
    }

    /// True when this store carries the group-encrypted policy.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        matches!(
            self.policy,
            AccessPolicy::Encrypted { .. } | AccessPolicy::TreeKemEncrypted { .. }
        )
    }

    #[must_use]
    pub fn is_treekem_encrypted(&self) -> bool {
        matches!(self.policy, AccessPolicy::TreeKemEncrypted { .. })
    }

    #[must_use]
    pub fn is_group_signed(&self) -> bool {
        matches!(self.policy, AccessPolicy::GroupSigned { .. })
    }

    /// Force-build a live replica carrying the reserved
    /// [`AccessPolicy::Encrypted`] policy, bypassing the [`new`](Self::new)
    /// reservation guard.
    ///
    /// **Test-only by design** (`#[cfg(test)]`, #341 Phase A): it exists
    /// solely so the fail-closed arms (`is_authorized`,
    /// `authorize_local_write`, `merge_delta`) can be proven against a
    /// replica that no ordinary constructor will build anymore. The only
    /// production-shaped way such a replica can exist is deserializing
    /// legacy state (snapshot/wire), which hits the same fail-closed paths.
    #[cfg(test)]
    pub(crate) fn new_encrypted_unchecked(
        id: KvStoreId,
        name: String,
        owner: AgentId,
        group_id: Vec<u8>,
    ) -> Self {
        let mut store = Self::new(id, name, owner, AccessPolicy::Signed)
            .expect("Signed policy is always constructible");
        store.policy = AccessPolicy::Encrypted { group_id };
        store
    }

    /// Create a joined replica of a store, anchoring ownership from trusted
    /// out-of-band input.
    ///
    /// Ownership is established ONLY here, at construction:
    /// - `expected_owner = Some(o)` → the replica is **anchored** on `o`
    ///   (`OwnershipSource::Anchored`). It accepts `o`'s deltas and (if this
    ///   node *is* `o`) its own local writes, converging against any owner
    ///   version — including a v0.30.1 owner that never announces — because
    ///   the data path never consults an announce.
    /// - `expected_owner = None` → the replica has **no owner**
    ///   (`OwnershipSource::Unknown`) and is permanently read-only by design:
    ///   every policy-restricted write returns [`KvError::OwnerUnknown`]. This
    ///   is explicit incompatibility, never a silent deadlock and never a
    ///   permissive first-writer fallback.
    ///
    /// `channel` records how the anchor was supplied (audit metadata).
    #[must_use]
    pub fn new_replica(
        id: KvStoreId,
        name: String,
        expected_owner: Option<AgentId>,
        channel: AnchorChannel,
    ) -> Self {
        Self {
            id,
            keys: OrSet::new(),
            entries: HashMap::new(),
            name: LwwRegister::new(name),
            policy: AccessPolicy::Signed,
            owner: expected_owner,
            anchor_channel: channel,
            policy_version: 0,
            ownership_conflict: None,
            last_history_endorser: None,
            latest_checkpoint: None,
            highest_checkpoint_seq: 0,
            allowed_writers: HashSet::new(),
            version: 0,
            seq_counter: Arc::new(AtomicU64::new(0)),
            secure: None,
            image: ImageAdmission::default(),
            orset_digest_cache: OrsetDigestCache::default(),
        }
    }

    /// Create a new owner-free [`AccessPolicy::SelfKeyed`] directory store.
    ///
    /// `owner` is `None` for life: write authority is the key-prefix binding
    /// ([`key_agent_prefix`]), not an owner anchor, so `OwnerUnknown` never
    /// fires on this store. Named separately from
    /// [`new_replica`](Self::new_replica) so that path cannot drift into an
    /// owner-free writable mode.
    #[must_use]
    pub fn new_self_keyed(id: KvStoreId, name: String) -> Self {
        Self {
            id,
            keys: OrSet::new(),
            entries: HashMap::new(),
            name: LwwRegister::new(name),
            policy: AccessPolicy::SelfKeyed,
            owner: None,
            anchor_channel: AnchorChannel::Persistence,
            policy_version: 0,
            ownership_conflict: None,
            last_history_endorser: None,
            latest_checkpoint: None,
            highest_checkpoint_seq: 0,
            allowed_writers: HashSet::new(),
            version: 0,
            seq_counter: Arc::new(AtomicU64::new(0)),
            secure: None,
            image: ImageAdmission::default(),
            orset_digest_cache: OrsetDigestCache::default(),
        }
    }

    /// Create a joined replica of an owner-free
    /// [`AccessPolicy::SelfKeyed`] directory store.
    ///
    /// Same shape as [`new_self_keyed`](Self::new_self_keyed); named
    /// separately so a future edit to one cannot silently change the other.
    #[must_use]
    pub fn join_self_keyed(id: KvStoreId, name: String) -> Self {
        Self::new_self_keyed(id, name)
    }

    /// Get the next monotonically-increasing sequence number.
    pub fn next_seq(&self) -> Result<u64> {
        self.reserve_sequences(1)
    }

    /// Verify that `count` sequence numbers can be minted without wrapping.
    pub(crate) fn reserve_sequences(&self, count: u64) -> Result<u64> {
        if count == 0 {
            return Err(KvError::Merge(
                "cannot reserve zero local sequence numbers".to_string(),
            ));
        }
        self.seq_counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(count)
            })
            .map(|previous| previous + 1)
            .map_err(|_| KvError::Merge("local sequence allocator is exhausted".to_string()))
    }

    /// Current value of the in-memory sequence counter (highest seq minted).
    ///
    /// Snapshot persistence stores this alongside the store state so a
    /// restart can restore the exact tag ceiling — `seq_counter` itself is
    /// `serde(skip)` for wire/legacy-layout reasons.
    pub(crate) fn seq_counter_value(&self) -> u64 {
        self.seq_counter.load(Ordering::Relaxed)
    }

    /// Restore the in-memory sequence counter to at least `floor`.
    ///
    /// Called on snapshot restore with the persisted counter value so a
    /// restarted node can never re-mint an OR-Set `(peer, seq)` tag it used
    /// before the restart. (`KvStoreHandle::put_with_delta` mints a second
    /// seq per put for the published delta tag, so the counter deliberately
    /// runs ahead of `version` — persisting the real counter, not a
    /// version-derived floor, is what makes this bound exact.)
    pub(crate) fn restore_seq_counter(&self, floor: u64) {
        self.seq_counter.fetch_max(floor, Ordering::Relaxed);
    }

    /// Give this store its own sequence allocator at the current counter.
    ///
    /// [`Clone`] shares the `Arc<AtomicU64>`. `merge_legacy_signed_history`
    /// then `fetch_max`s that allocator, so a trial clone would move the live
    /// counter even when the caller discards the trial. Detach before the
    /// trial merge. Move the trial into the live store only if the merge is
    /// accepted; dropping the trial leaves the live allocator untouched.
    pub(crate) fn detach_seq_counter(&mut self) {
        let current = self.seq_counter.load(Ordering::Relaxed);
        self.seq_counter = Arc::new(AtomicU64::new(current));
    }

    /// Convert a store decoded through the frozen v1 (≤ v0.45.0) snapshot
    /// shape into the current in-memory form. Every field added after
    /// v0.45.0 takes its default; the struct literal is exhaustive so a new
    /// `KvStore` field cannot be added without deciding its v1 default here.
    pub(crate) fn from_v1_snapshot_shape(v1: KvStoreV1SnapshotShape) -> Self {
        let KvStoreV1SnapshotShape {
            id,
            keys,
            entries,
            name,
            policy,
            owner,
            allowed_writers,
            version,
            latest_checkpoint,
            highest_checkpoint_seq,
            anchor_channel,
            policy_version,
            ownership_conflict,
        } = v1;
        Self {
            id,
            keys,
            entries,
            name,
            policy,
            owner,
            allowed_writers,
            version,
            latest_checkpoint,
            highest_checkpoint_seq,
            anchor_channel,
            policy_version,
            ownership_conflict,
            last_history_endorser: None,
            seq_counter: default_seq_counter(),
            secure: None,
            image: ImageAdmission::default(),
            orset_digest_cache: OrsetDigestCache::default(),
        }
    }

    /// Get the current version.
    #[must_use]
    pub fn current_version(&self) -> u64 {
        self.version
    }

    /// Get the store ID.
    #[must_use]
    pub fn id(&self) -> &KvStoreId {
        &self.id
    }

    /// Get the store name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.get()
    }

    /// The name register, including its vector clock.
    ///
    /// Deltas carry this whole register (not just the value) so receivers can
    /// resolve a remote name change by causality rather than adopting it
    /// unconditionally.
    #[must_use]
    pub fn name_register(&self) -> &LwwRegister<String> {
        &self.name
    }

    /// Get the access policy.
    #[must_use]
    pub fn policy(&self) -> &AccessPolicy {
        &self.policy
    }

    /// Get the store owner.
    #[must_use]
    pub fn owner(&self) -> Option<&AgentId> {
        self.owner.as_ref()
    }

    /// Get the policy-version freshness counter.
    #[must_use]
    pub fn policy_version(&self) -> u64 {
        self.policy_version
    }

    /// Get the channel through which the owner was anchored.
    #[must_use]
    pub fn anchor_channel(&self) -> AnchorChannel {
        self.anchor_channel
    }

    /// Derive the store's ownership status for auditability.
    ///
    /// This is a *view* of the authoritative `owner` field plus the last
    /// observed conflict — writes are gated on `owner`/`policy`, never on
    /// this value.
    #[must_use]
    pub fn ownership_source(&self) -> OwnershipSource {
        match (&self.owner, &self.ownership_conflict) {
            (None, _) => OwnershipSource::Unknown,
            (Some(owner), None) => OwnershipSource::Anchored {
                owner: *owner,
                channel: self.anchor_channel,
            },
            (Some(owner), Some((_anchored, announced))) => OwnershipSource::Conflict {
                // `anchored` is the current authoritative owner by construction.
                anchored: *owner,
                announced: *announced,
            },
        }
    }

    /// Get the set of allowed writers.
    #[must_use]
    pub fn allowed_writers(&self) -> &HashSet<AgentId> {
        &self.allowed_writers
    }

    /// Get the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether a group-signed retained-state response has causal history to
    /// serve. An active-empty store can still carry OR-Set tombstones after
    /// its last key was removed; any mutation advances `version`, so version
    /// zero is the only history-free state.
    #[must_use]
    pub(crate) fn has_retained_group_history(&self) -> bool {
        !self.is_empty() || self.version > 0
    }

    /// Check if an agent is authorized to write to this store.
    #[must_use]
    pub fn is_authorized(&self, agent_id: &AgentId) -> bool {
        match &self.policy {
            AccessPolicy::Signed => {
                // Only the owner can write
                self.owner.as_ref().is_some_and(|o| o == agent_id)
            }
            AccessPolicy::Allowlisted => {
                // Owner + allowlisted agents can write
                self.owner.as_ref().is_some_and(|o| o == agent_id)
                    || self.allowed_writers.contains(agent_id)
            }
            AccessPolicy::Encrypted { .. } | AccessPolicy::TreeKemEncrypted { .. } => {
                // Group-encrypted store (#341 Phase B): the v1 write rule is
                // ACTIVE GROUP MEMBERSHIP, evaluated by the attached secure
                // context. Without a context (reserved policy, or a replica
                // deserialized from a snapshot that has not been re-bound
                // yet) this stays fail-closed (#341 Phase A).
                self.secure
                    .as_ref()
                    .is_some_and(|ctx| ctx.is_authorized_writer(agent_id))
            }
            AccessPolicy::AppendOnly => {
                // Owner-only writes, exactly like Signed. Immutability of
                // existing keys is enforced separately at each mutation site
                // (put/remove/merge_delta/checkpoint adoption).
                self.owner.as_ref().is_some_and(|o| o == agent_id)
            }
            AccessPolicy::SelfKeyed => {
                // Fail-closed for the key-less store-wide predicate: a
                // SelfKeyed store has no owner and authority is per key
                // (I1/I3). Callers that forgot the key get `false`; the
                // mutation paths use `authorize_write` / `is_authorized_for_key`.
                false
            }
            AccessPolicy::GroupSigned { .. } => self
                .secure
                .as_ref()
                .is_some_and(|ctx| ctx.is_authorized_writer(agent_id)),
        }
    }

    /// Check that `writer` may write `key` under this store's policy.
    ///
    /// This is the key-aware authority predicate for
    /// [`AccessPolicy::SelfKeyed`] (I1: the key's agent prefix must equal
    /// `writer`); the owner-anchored policies ignore the key and apply their
    /// store-wide rule; the reserved [`AccessPolicy::Encrypted`] is
    /// fail-closed (#341 Phase A / #358).
    #[must_use]
    pub fn is_authorized_for_key(&self, writer: &AgentId, key: &str) -> bool {
        match &self.policy {
            AccessPolicy::SelfKeyed => key_agent_prefix(key) == Some(*writer),
            // Owner-anchored and reserved policies: key-independent.
            _ => self.is_authorized(writer),
        }
    }

    /// Enforce the store's access policy for a mutation of `key` by
    /// `writer`.
    ///
    /// The key-aware successor of [`authorize_local_write`](Self::authorize_local_write)
    /// and the local-write counterpart of the inbound check in
    /// [`merge_delta`](Self::merge_delta): the same rule is applied before a
    /// local put/remove mutates the replica, so an unauthorized local write
    /// can never fork the replica away from what authorized peers accept.
    ///
    /// # Errors
    ///
    /// - [`KvError::OwnerUnknown`] if an owner-anchored policy
    ///   (`Signed`/`Allowlisted`/`AppendOnly`) has no anchored owner.
    ///   Never returned for `SelfKeyed` (I3: it has no owner for life).
    /// - [`KvError::Unauthorized`] if `writer` is not authorized for `key`.
    pub fn authorize_write(&self, writer: &AgentId, key: &str) -> Result<()> {
        match &self.policy {
            AccessPolicy::Encrypted { group_id } | AccessPolicy::TreeKemEncrypted { group_id } => {
                // #341 Phase B: the v1 write rule is active group
                // membership, via the attached secure context. Without a
                // context this is the reserved fail-closed state — notably
                // this closes the Phase A hole where `authorize_write` (and
                // therefore local removes through the handle layer) was
                // unconditionally permissive on a reserved Encrypted store.
                match self.secure.as_ref() {
                    Some(ctx) if ctx.is_authorized_writer(writer) => Ok(()),
                    Some(_) => Err(KvError::Unauthorized(format!(
                        "encrypted store: writer {} is not an authorized writer in group {}",
                        hex::encode(writer.as_bytes()),
                        hex::encode(group_id)
                    ))),
                    None => Err(KvError::EncryptedPolicyReserved {
                        group_id: group_id.clone(),
                    }),
                }
            }
            AccessPolicy::GroupSigned { group_id } => match self.secure.as_ref() {
                Some(ctx) if ctx.is_authorized_writer(writer) => Ok(()),
                Some(_) => Err(KvError::Unauthorized(format!(
                    "group-signed store: writer {} is not authorized for group {}",
                    hex::encode(writer.as_bytes()),
                    hex::encode(group_id)
                ))),
                None => Err(KvError::Unauthorized(
                    "group-signed store has no current group context".to_string(),
                )),
            },
            AccessPolicy::SelfKeyed => {
                if self.is_authorized_for_key(writer, key) {
                    Ok(())
                } else {
                    Err(KvError::Unauthorized(format!(
                        "self_keyed store: key {key:?} is not bound to writer {}",
                        hex::encode(writer.as_bytes())
                    )))
                }
            }
            AccessPolicy::Signed | AccessPolicy::Allowlisted | AccessPolicy::AppendOnly => {
                let Some(owner) = self.owner.as_ref() else {
                    return Err(KvError::OwnerUnknown);
                };
                if !self.is_authorized_for_key(writer, key) {
                    return Err(KvError::Unauthorized(format!(
                        "store policy is {}; owner is {}",
                        self.policy,
                        hex::encode(owner.as_bytes())
                    )));
                }
                Ok(())
            }
        }
    }

    /// Enforce authority AND the `SelfKeyed` per-agent quota for a local put
    /// of `value` under `key`.
    ///
    /// Applies the SAME deterministic lowest-N admission predicate as the
    /// remote merge path (`merge_delta`), so a local write that peers would
    /// drop never mutates this replica. Authority is checked first
    /// (`Unauthorized` wins over the quota); `MAX_INLINE_SIZE` is checked
    /// before the quota so a single oversized value still surfaces as
    /// [`KvError::ValueTooLarge`].
    ///
    /// This gates only the INCOMING key: `put` additionally trims the
    /// writer's live set down to the admitted subset (same predicate), so a
    /// local put can evict the writer's existing lex-high keys.
    ///
    /// # Errors
    ///
    /// As [`authorize_write`](Self::authorize_write), plus
    /// [`KvError::AgentQuotaExceeded`] when the put would fall outside the
    /// writer's admitted lowest-N set, and [`KvError::ValueTooLarge`] for a
    /// single value above the inline maximum.
    pub fn authorize_put(&self, writer: &AgentId, key: &str, value: &[u8]) -> Result<()> {
        self.authorize_write(writer, key)?;
        if matches!(self.policy, AccessPolicy::SelfKeyed) {
            if value.len() > crate::kv::entry::MAX_INLINE_SIZE {
                return Err(KvError::ValueTooLarge {
                    size: value.len(),
                    max: crate::kv::entry::MAX_INLINE_SIZE,
                });
            }
            self.check_self_keyed_admission(writer, key, value.len())?;
        }
        Ok(())
    }

    /// Check that `writer` may perform a local mutation on this store.
    ///
    /// This is the local-write counterpart of the inbound check in
    /// [`merge_delta`](Self::merge_delta): the same
    /// [`is_authorized`](Self::is_authorized) rule is applied before a local
    /// put/remove mutates the replica, so an unauthorized local write can
    /// never fork
    /// the replica away from what authorized peers accept.
    ///
    /// # Errors
    ///
    /// - [`KvError::EncryptedPolicyReserved`] if the store carries the
    ///   reserved [`AccessPolicy::Encrypted`] policy: secure sync is not
    ///   wired, so no local write may mutate such a replica (fail closed).
    /// - [`KvError::OwnerUnknown`] if the store has a policy-restricted
    ///   (`Signed`/`Allowlisted`) policy but its authoritative owner has not
    ///   been learned yet (a freshly joined replica). Fail closed.
    /// - [`KvError::Unauthorized`] if `writer` is not authorized under the
    ///   store's policy.
    pub fn authorize_local_write(&self, writer: &AgentId) -> Result<()> {
        if let AccessPolicy::Encrypted { group_id } | AccessPolicy::TreeKemEncrypted { group_id } =
            &self.policy
        {
            // #341 Phase B: with an attached secure context the v1 write
            // rule is active group membership. Without one this is the
            // reserved fail-closed state — loudly, and never `OwnerUnknown`
            // (this is not an ownership issue).
            return match self.secure.as_ref() {
                Some(ctx) if ctx.is_authorized_writer(writer) => Ok(()),
                Some(_) => {
                    tracing::warn!(
                        target: "x0x::kv",
                        "refused local write by {} on encrypted store {} (group_id {}) — writer is not authorized by the current group policy",
                        hex::encode(writer.as_bytes()),
                        self.id,
                        hex::encode(group_id)
                    );
                    Err(KvError::Unauthorized(format!(
                        "encrypted store: writer {} is not an authorized writer in group {}",
                        hex::encode(writer.as_bytes()),
                        hex::encode(group_id)
                    )))
                }
                None => {
                    tracing::warn!(
                        target: "x0x::kv",
                        "refused local write by {} on reserved encrypted store {} (group_id {}) — no secure context attached; secure sync is not wired",
                        hex::encode(writer.as_bytes()),
                        self.id,
                        hex::encode(group_id)
                    );
                    Err(KvError::EncryptedPolicyReserved {
                        group_id: group_id.clone(),
                    })
                }
            };
        }
        if let AccessPolicy::GroupSigned { group_id } = &self.policy {
            return match self.secure.as_ref() {
                Some(ctx) if ctx.is_authorized_writer(writer) => Ok(()),
                Some(_) => Err(KvError::Unauthorized(format!(
                    "group-signed store: writer {} is not authorized for group {}",
                    hex::encode(writer.as_bytes()),
                    hex::encode(group_id)
                ))),
                None => Err(KvError::Unauthorized(
                    "group-signed store has no current group context".to_string(),
                )),
            };
        }
        if matches!(self.policy, AccessPolicy::SelfKeyed) {
            // Legacy key-less check: a SelfKeyed store cannot validate the
            // prefix binding without a key. Fail closed WITHOUT OwnerUnknown
            // (I3 — the store deliberately has no owner); the mutation paths
            // use the key-aware `authorize_write` / `authorize_put`.
            return Err(KvError::Unauthorized(
                "self_keyed store: authorization is per key — use authorize_write(writer, key)"
                    .to_string(),
            ));
        }
        let Some(owner) = self.owner.as_ref() else {
            return Err(KvError::OwnerUnknown);
        };
        if !self.is_authorized(writer) {
            return Err(KvError::Unauthorized(format!(
                "store policy is {}; owner is {}",
                self.policy,
                hex::encode(owner.as_bytes())
            )));
        }
        Ok(())
    }

    /// Apply an owner-announced policy refresh / detect a conflict.
    ///
    /// `verified_sender` is the cryptographically verified identity of the
    /// peer that published the announcement (the pub/sub layer verifies the
    /// ML-DSA-65 signature before delivery). The `claimed_owner` must equal
    /// `verified_sender`: an announce can only attest to *oneself*, blocking
    /// third-party ownership assignment.
    ///
    /// **Ownership is NEVER established here.** Ownership is anchored only at
    /// construction ([`new`](Self::new) / [`new_replica`](Self::new_replica)).
    /// The `verified_sender == claimed_owner` check blocks third-party
    /// assignment but is *trivially* satisfied by any self-claim, so accepting
    /// an announce to go `None → Some(owner)` would let any agent that speaks
    /// first about a topic seize it (first-self-capture). That path is removed
    /// by construction.
    ///
    /// This method therefore only ever:
    /// - **refreshes policy** when the claimed owner equals the already-anchored
    ///   owner AND `policy_version` is strictly newer than the last applied
    ///   refresh (blocking a replayed authentic-but-stale announce from
    ///   downgrading policy); or
    /// - **records a conflict** when the claimed owner differs from the
    ///   anchored owner (the anchored owner is unchanged; the conflict is
    ///   surfaced via [`ownership_source`](Self::ownership_source)).
    ///
    /// # Errors
    ///
    /// - [`KvError::OwnerTokenInvalid`] if `verified_sender != claimed_owner`,
    ///   or if the store has no anchored owner (`None` — ownership cannot be
    ///   learned from an untrusted announce; the caller must supply
    ///   `expected_owner` at join).
    /// - [`KvError::OwnershipConflict`] if a different owner is anchored.
    pub fn learn_ownership(
        &mut self,
        claimed_owner: AgentId,
        policy: AccessPolicy,
        policy_version: u64,
        verified_sender: &AgentId,
    ) -> Result<()> {
        match self.check_ownership_announce(
            claimed_owner,
            &policy,
            policy_version,
            verified_sender,
        )? {
            OwnershipAnnounceEffect::Conflict { anchored } => {
                // Immutable owner: record the conflict for auditability and reject.
                self.ownership_conflict = Some((anchored, claimed_owner));
                self.bump_version_keeping_content();
                Err(KvError::OwnershipConflict {
                    anchored,
                    claimed: claimed_owner,
                })
            }
            OwnershipAnnounceEffect::Refresh => {
                self.policy = policy;
                self.policy_version = policy_version;
                self.ownership_conflict = None;
                self.bump_version_keeping_content();
                Ok(())
            }
            OwnershipAnnounceEffect::Stale => Ok(()),
        }
    }

    /// Read-only half of [`learn_ownership`](Self::learn_ownership): every
    /// validation it performs, and what it WOULD do, without mutating. Lets
    /// the sync responder reject or skip an announce without entering its
    /// receive section (#757).
    ///
    /// # Errors
    ///
    /// The same rejections as `learn_ownership`, except an owner conflict,
    /// which is reported as [`OwnershipAnnounceEffect::Conflict`] because
    /// recording it is a mutation.
    pub(crate) fn check_ownership_announce(
        &self,
        claimed_owner: AgentId,
        policy: &AccessPolicy,
        policy_version: u64,
        verified_sender: &AgentId,
    ) -> Result<OwnershipAnnounceEffect> {
        if *verified_sender != claimed_owner {
            return Err(KvError::OwnerTokenInvalid(
                "ownership announcement sender does not match claimed owner".to_string(),
            ));
        }
        let Some(existing) = self.owner else {
            // No anchored owner. Ownership is construction-only: refuse to
            // derive it from an untrusted announce. Remain read-only.
            return Err(KvError::OwnerTokenInvalid(
                "ownership cannot be learned from an announcement; supply expected_owner at join"
                    .to_string(),
            ));
        };
        if existing != claimed_owner {
            // Immutable owner: the caller records the conflict and rejects.
            return Ok(OwnershipAnnounceEffect::Conflict { anchored: existing });
        }
        // Anchored owner matches. Apply the policy refresh when it is at least
        // as fresh as the last applied one. `>=` (not strict `>`) is required
        // so a fresh replica at version 0 adopts the owner's initial (version
        // 0) policy — otherwise a non-Signed store would stay at the default
        // Signed and reject legitimate writers. Equal-version replay is safe:
        // a legitimate owner assigns each policy a unique monotonic version,
        // so an equal version carries the same policy, and a forgery with a
        // different policy at the same version cannot be signed by the owner.
        // An older replay (version < current) is still dropped, preventing a
        // downgrade. A matching forward refresh clears a recorded conflict.
        //
        // AppendOnly is TERMINAL: once this replica knows the store is
        // append-only, no announce — however fresh, however genuinely
        // owner-signed — may transition the policy away from it. Allowing
        // that would let the owner downgrade to Signed, delete/rewrite keys,
        // and (optionally) upgrade back: exactly the retroactive-rewrite
        // attack AppendOnly exists to stop.
        if matches!(self.policy, AccessPolicy::AppendOnly)
            && !matches!(policy, AccessPolicy::AppendOnly)
        {
            return Err(KvError::OwnerTokenInvalid(
                "append-only policy is terminal; policy downgrade rejected".to_string(),
            ));
        }
        // Encrypted is TERMINAL the same way (#341 Phase B): members joined
        // on the confidentiality promise, so no owner announce — however
        // authentic — may silently un-encrypt the store (that would flip
        // every replica back onto plaintext gossip paths). A refresh to a
        // DIFFERENT group binding is equally rejected.
        if let AccessPolicy::Encrypted {
            group_id: anchored_group,
        } = &self.policy
        {
            match policy {
                AccessPolicy::Encrypted {
                    group_id: announce_group,
                } if announce_group == anchored_group => {}
                _ => {
                    return Err(KvError::OwnerTokenInvalid(
                        "encrypted policy is terminal; confidentiality downgrade rejected"
                            .to_string(),
                    ));
                }
            }
        }
        if let AccessPolicy::TreeKemEncrypted {
            group_id: anchored_group,
        } = &self.policy
        {
            match policy {
                AccessPolicy::TreeKemEncrypted {
                    group_id: announce_group,
                } if announce_group == anchored_group => {}
                _ => {
                    return Err(KvError::OwnerTokenInvalid(
                        "TreeKEM encrypted policy is terminal; confidentiality downgrade rejected"
                            .to_string(),
                    ));
                }
            }
        }
        if policy_version >= self.policy_version {
            Ok(OwnershipAnnounceEffect::Refresh)
        } else {
            Ok(OwnershipAnnounceEffect::Stale)
        }
    }

    /// Add an agent to the allowlist (owner-only operation).
    ///
    /// # Errors
    ///
    /// Returns `KvError::Unauthorized` if the caller is not the owner.
    pub fn allow_writer(&mut self, writer: AgentId, caller: &AgentId) -> Result<()> {
        if !self.owner.as_ref().is_some_and(|o| o == caller) {
            return Err(KvError::Unauthorized(
                "only the store owner can modify the allowlist".to_string(),
            ));
        }
        self.allowed_writers.insert(writer);
        // Bump the policy freshness counter so the owner's next announce
        // carries a newer version (blocks replay of a pre-change announce).
        self.policy_version = self.policy_version.saturating_add(1);
        self.bump_version_keeping_content();
        Ok(())
    }

    /// Remove an agent from the allowlist (owner-only operation).
    ///
    /// # Errors
    ///
    /// Returns `KvError::Unauthorized` if the caller is not the owner.
    pub fn deny_writer(&mut self, writer: &AgentId, caller: &AgentId) -> Result<()> {
        if !self.owner.as_ref().is_some_and(|o| o == caller) {
            return Err(KvError::Unauthorized(
                "only the store owner can modify the allowlist".to_string(),
            ));
        }
        self.allowed_writers.remove(writer);
        self.policy_version = self.policy_version.saturating_add(1);
        self.bump_version_keeping_content();
        Ok(())
    }

    /// Put a key-value entry.
    ///
    /// If the key already exists, the value is updated using LWW semantics —
    /// except under [`AccessPolicy::AppendOnly`], where an existing key is
    /// immutable: a re-put of byte-identical content (same value AND
    /// content type) is accepted as an idempotent no-op so retries are safe,
    /// and anything else returns [`KvError::ImmutableKey`].
    ///
    /// Under [`AccessPolicy::SelfKeyed`], the writer's live set is trimmed to
    /// the admitted lowest-N subset after the entry lands — the same rule
    /// the remote merge applies — so a local put can evict the writer's
    /// lex-highest keys.
    pub fn put(
        &mut self,
        key: String,
        value: Vec<u8>,
        content_type: String,
        peer_id: PeerId,
    ) -> Result<()> {
        if !self.preflight_put_content(&key, &value, &content_type)? {
            return Ok(());
        }
        let seq = self.reserve_sequences(1)?;
        self.put_with_reserved_sequence(key, value, content_type, peer_id, seq)?;
        Ok(())
    }

    /// Validate deterministic content constraints before reserving a local
    /// sequence. Returns `false` only for an AppendOnly idempotent re-put.
    pub(crate) fn preflight_put_content(
        &self,
        key: &str,
        value: &[u8],
        content_type: &str,
    ) -> Result<bool> {
        if value.len() > crate::kv::entry::MAX_INLINE_SIZE {
            return Err(KvError::ValueTooLarge {
                size: value.len(),
                max: crate::kv::entry::MAX_INLINE_SIZE,
            });
        }
        if matches!(self.policy, AccessPolicy::AppendOnly) {
            if let Some(existing) = self.get(key) {
                if existing.value == value && existing.content_type == content_type {
                    return Ok(false);
                }
                return Err(KvError::ImmutableKey(key.to_string()));
            }
        }
        Ok(true)
    }

    pub(crate) fn put_with_reserved_sequence(
        &mut self,
        key: String,
        value: Vec<u8>,
        content_type: String,
        peer_id: PeerId,
        seq: u64,
    ) -> Result<Vec<String>> {
        if value.len() > crate::kv::entry::MAX_INLINE_SIZE {
            return Err(KvError::ValueTooLarge {
                size: value.len(),
                max: crate::kv::entry::MAX_INLINE_SIZE,
            });
        }

        // AppendOnly: existing keys are immutable, even for the owner.
        if matches!(self.policy, AccessPolicy::AppendOnly) {
            if let Some(existing) = self.get(&key) {
                if existing.value == value && existing.content_type == content_type {
                    return Ok(Vec::new()); // idempotent re-put of identical content
                }
                return Err(KvError::ImmutableKey(key));
            }
        }

        // Captured before `key` is consumed below: the SelfKeyed live-set cap
        // is enforced after the entry lands.
        let self_keyed_writer = if matches!(self.policy, AccessPolicy::SelfKeyed) {
            key_agent_prefix(&key)
        } else {
            None
        };

        // Add key to OR-Set
        self.keys
            .add(key.clone(), (peer_id, seq))
            .map_err(|e| KvError::Merge(format!("OR-Set add failed: {e}")))?;

        // Create or update entry
        if let Some(existing) = self.entries.get_mut(&key) {
            existing.update_value(value, content_type);
        } else {
            self.entries
                .insert(key.clone(), KvEntry::new(key, value, content_type));
        }

        // SelfKeyed live-set cap (I7): the quota bounds the live set, not
        // just the write. `authorize_put` gates only the incoming key, so
        // without this the local replica would keep the writer's over-cap
        // lex-high keys that every remote evicts at step 4.
        let evicted = match self_keyed_writer {
            Some(writer) => self.enforce_self_keyed_live_set(&writer),
            None => Vec::new(),
        };
        if self.serves_retained_group_image() {
            self.keys.compact(0);
        }

        self.version += 1;
        Ok(evicted)
    }

    /// #1094 P1 / #1970: refuse a local put of `key` that would take this
    /// store's retained image past the soft limit
    /// ([`SOFT_IMAGE_LIMIT_BYTES`]). `marked` adds a writer mark's bytes.
    /// The growth is an upper estimate: the new entry, its map key and a new
    /// key tag, less the entry it replaces.
    ///
    /// # Errors
    ///
    /// [`KvError::StoreFull`] when the image would pass the soft limit.
    pub fn check_image_room(
        &self,
        key: &str,
        value_len: usize,
        content_type_len: usize,
        marked: bool,
    ) -> Result<()> {
        let max = SOFT_IMAGE_LIMIT_BYTES;
        let mark = if marked { WRITER_MARK_BYTES } else { 0 };
        let entry = ENTRY_FIXED_BYTES + 2 * key.len() + value_len + content_type_len + mark;
        let tag = KEY_TAG_BYTES + key.len();
        let replaced = self.entry_len(key);
        let rest = self.admission_rest_len()?;
        let image_with = |content: u64| {
            content
                .saturating_add(rest)
                .saturating_add((entry + tag) as u64)
                .saturating_sub(replaced)
        };
        if let Some(bound) = self.image.cached_content(self.version, self.keys.version()) {
            if image_with(bound) <= max as u64 {
                return Ok(());
            }
        }
        let image = image_with(self.content_len()?);
        if image > max as u64 {
            return Err(KvError::StoreFull { image, max });
        }
        Ok(())
    }

    /// #1970: whether this store serves its complete state as a retained
    /// group image, and so lives under the retained-image limits. Mirrors
    /// the store kinds `merge_group_retained_image` admits.
    pub(crate) fn serves_retained_group_image(&self) -> bool {
        matches!(
            self.policy,
            AccessPolicy::GroupSigned { .. }
                | AccessPolicy::Encrypted { .. }
                | AccessPolicy::TreeKemEncrypted { .. }
        )
    }

    /// #1970: the bytes this store retains, in memory and on disk: its
    /// bincode length, every entry and the OR-Set with its changelog
    /// included. The test `the_retained_measure_is_the_stored_bytes` pins
    /// it to `bincode::serialized_size`.
    pub(crate) fn retained_image_len(&self) -> Result<u64> {
        self.retained_with_content(self.content_len()?)
    }

    /// [`Self::retained_image_len`] with the content length given.
    fn retained_with_content(&self, content: u64) -> Result<u64> {
        Ok(content
            .saturating_add(self.replicated_rest_len()?)
            .saturating_add(self.local_len()?))
    }

    /// #1970: the size the admission rule compares with the hard limit: the
    /// replicated part of the retained image plus [`LOCAL_IMAGE_ALLOWANCE`]
    /// for the per-replica fields (or their real size, if larger). It is at
    /// least [`Self::retained_image_len`], and two replicas with the same
    /// replicated state compute the same value.
    #[cfg(test)]
    pub(crate) fn admission_image_len(&self) -> Result<u64> {
        Ok(self
            .content_len()?
            .saturating_add(self.admission_rest_len()?))
    }

    /// The OR-Set and the entries, walked by length: no value bytes are read
    /// and nothing is allocated.
    fn content_len(&self) -> Result<u64> {
        #[cfg(test)]
        FULL_MEASURES.with(|n| n.set(n.get() + 1));
        let keys = bincode::serialized_size(&self.keys)?;
        let entries = self.entries.iter().fold(8u64, |sum, (key, entry)| {
            sum.saturating_add(8 + key.len() as u64)
                .saturating_add(entry.wire_len())
        });
        Ok(keys.saturating_add(entries))
    }

    /// Replicated fields besides the OR-Set and the entries.
    fn replicated_rest_len(&self) -> Result<u64> {
        Ok(bincode::serialized_size(&(
            &self.id,
            &self.name,
            &self.policy,
            &self.owner,
            &self.allowed_writers,
        ))?)
    }

    /// Per-replica fields: they can differ between replicas that hold the
    /// same replicated state.
    fn local_len(&self) -> Result<u64> {
        Ok(bincode::serialized_size(&(
            self.version,
            &self.latest_checkpoint,
            self.highest_checkpoint_seq,
            &self.anchor_channel,
            self.policy_version,
            &self.ownership_conflict,
            &self.last_history_endorser,
        ))?)
    }

    fn admission_rest_len(&self) -> Result<u64> {
        Ok(self
            .replicated_rest_len()?
            .saturating_add(self.local_len()?.max(LOCAL_IMAGE_ALLOWANCE)))
    }

    /// The bytes of `key`'s entry and its map key, or 0.
    fn entry_len(&self, key: &str) -> u64 {
        self.entries
            .get(key)
            .map_or(0, |entry| 8 + key.len() as u64 + entry.wire_len())
    }

    /// The bytes of `key`'s live and tombstone slots in the OR-Set
    /// encoding. With an empty changelog the OR-Set encodes to 40 fixed
    /// bytes plus this sum over its keys (`OrSet::retained_tags`).
    fn orset_key_len(&self, key: &String) -> u64 {
        let tags = self.keys.retained_tags(key);
        let slot = |n: Option<usize>| {
            n.map_or(0, |n| {
                (16 + key.len() as u64).saturating_add((n as u64).saturating_mul(ORSET_TAG_BYTES))
            })
        };
        slot(tags.live).saturating_add(slot(tags.tombstoned))
    }

    /// The exact content part of the image: the cached length while no
    /// other mutation has happened, else a measure, which is then cached.
    /// A cached length is exact only while the OR-Set changelog is empty,
    /// as it is after every settle.
    fn content_exact(&mut self) -> Result<u64> {
        if self.keys.changelog_len() != 0 {
            // Compacting does not move the OR-Set version, so a cached
            // length taken with changelog entries would stay keyed as
            // valid after they are gone.
            self.keys.compact(0);
            self.image.invalidate_content();
        }
        if let Some(exact) = self.image.cached_content(self.version, self.keys.version()) {
            return Ok(exact);
        }
        let exact = self.content_len()?;
        self.image
            .set_content(self.version, self.keys.version(), exact);
        Ok(exact)
    }

    /// Upper bounds on how much `delta` can grow the OR-Set, the entries
    /// and the replicated fields. An OR-Set add costs at most one tag, plus
    /// the key's map slot when the key is not live; a removal never grows
    /// it. A merged entry is one of the two entries merged.
    fn delta_growth_bound(&self, delta: &KvStoreDelta) -> Result<(u64, u64, u64)> {
        let tag = bincode::serialized_size(&(PeerId::new([0; 32]), 0u64))?;
        let slot = |key: &str| 16 + key.len() as u64;
        let mut keys = 0u64;
        let mut entries = 0u64;
        let incoming = delta
            .added
            .iter()
            .map(|(key, (entry, _))| {
                let add = if self.keys.contains(key) {
                    tag
                } else {
                    slot(key) + tag
                };
                (key, entry, add)
            })
            .chain(
                delta
                    .updated
                    .iter()
                    .map(|(key, entry)| (key, entry, slot(key) + tag)),
            );
        for (key, entry, add) in incoming {
            keys = keys.saturating_add(add);
            let local = self.entries.get(key).map_or(0, KvEntry::wire_len);
            let after = 8 + key.len() as u64 + local.max(entry.wire_len());
            entries = entries.saturating_add(after.saturating_sub(self.entry_len(key)));
        }
        let rest = bincode::serialized_size(&delta.allowlist_additions)?
            .saturating_add(bincode::serialized_size(&delta.name_update)?)
            .saturating_add(bincode::serialized_size(&delta.owner_checkpoint)?);
        Ok((keys, entries, rest))
    }

    /// #2110: a lower bound on the admission image after `delta` less the
    /// cached content length, so a delta whose lowest result is over the
    /// hard limit is refused before anything is copied or applied. It never
    /// exceeds the real result:
    /// - A key added and not removed is live afterwards with its new tag,
    ///   and its entry is the local or the incoming one (one LWW rule).
    /// - Any other touched key can lose all its OR-Set slots and its entry.
    /// - The name register can shrink to nothing, each allowlist removal
    ///   frees at most one agent id, and the per-replica fields count at
    ///   least [`LOCAL_IMAGE_ALLOWANCE`].
    fn delta_lowest_growth(&self, delta: &KvStoreDelta, touched: &[String]) -> Result<i128> {
        let mut growth = 0i128;
        for key in touched {
            let slots = i128::from(self.orset_key_len(key));
            let entry = i128::from(self.entry_len(key));
            let kept = match delta.added.get(key) {
                Some((incoming, _)) if !delta.removed.contains_key(key) => {
                    let slot = 16 + key.len() as u64 + ORSET_TAG_BYTES;
                    let local = self.entries.get(key).map_or(u64::MAX, KvEntry::wire_len);
                    let value = 8 + key.len() as u64 + local.min(incoming.wire_len());
                    i128::from(slot) + i128::from(value)
                }
                _ => 0,
            };
            growth += kept - slots - entry;
        }
        let mut rest = i128::from(self.replicated_rest_len()?);
        if delta.name_update.is_some() {
            rest -= i128::from(bincode::serialized_size(&self.name)?);
        }
        let freed = delta
            .allowlist_removals
            .as_ref()
            .map_or(0, |r| r.len() as u64);
        rest -= i128::from(freed.saturating_mul(32));
        Ok(growth + rest + i128::from(LOCAL_IMAGE_ALLOWANCE))
    }

    /// The exact change in entry bytes that `journal` recorded.
    fn journal_entry_delta(&self, journal: &EntryJournal) -> i128 {
        journal
            .priors
            .iter()
            .map(|(key, prior)| {
                let now = i128::from(self.entry_len(key));
                let before = match prior {
                    EntryPrior::Absent => 0,
                    EntryPrior::Entry(entry) => i128::from(8 + key.len() as u64 + entry.wire_len()),
                    EntryPrior::CreatedAt(_) => now,
                };
                now - before
            })
            .sum()
    }

    /// #1970: keep only retained state after a merge. An entry whose key is
    /// not live is dropped (the OR-Set keeps its tombstones, which is all
    /// convergence needs), and the OR-Set changelog is cleared: nothing
    /// reads it, since store deltas are built from the entries. `keys`
    /// limits the entry check to the keys a delta touched.
    fn settle_retained(&mut self, keys: Option<&[String]>, journal: &mut EntryJournal) {
        let every: Vec<String>;
        let candidates = match keys {
            Some(keys) => keys,
            None => {
                every = self.entries.keys().cloned().collect();
                &every
            }
        };
        for key in candidates {
            if !self.keys.contains(key) {
                self.journal_remove_entry(key, journal);
            }
        }
        self.keys.compact(0);
    }

    /// #1970: drop dead entries and the OR-Set changelog of a group store
    /// loaded from disk; an earlier version could leave both behind.
    pub(crate) fn settle_loaded(&mut self) {
        if self.serves_retained_group_image() {
            self.settle_retained(None, &mut EntryJournal::default());
        }
    }

    /// #1970: the retained image as a serve publishes it, encoded in place
    /// (no copy of the store): the `KvStore` bincode layout with the OR-Set
    /// in its canonical retained form.
    ///
    /// # Errors
    ///
    /// [`KvError::StoreFull`] when the image is above the hard limit;
    /// [`KvError::Serialization`] if encoding fails.
    pub(crate) fn encode_retained_image(&self) -> Result<Vec<u8>> {
        let image = self.retained_image_len()?;
        if image > HARD_IMAGE_LIMIT_BYTES as u64 {
            return Err(KvError::StoreFull {
                image,
                max: HARD_IMAGE_LIMIT_BYTES,
            });
        }
        #[derive(Serialize)]
        struct View<'a> {
            id: &'a KvStoreId,
            keys: saorsa_gossip_crdt_sync::CanonicalRetainedOrSet<String>,
            entries: &'a HashMap<String, KvEntry>,
            name: &'a LwwRegister<String>,
            policy: &'a AccessPolicy,
            owner: &'a Option<AgentId>,
            allowed_writers: &'a HashSet<AgentId>,
            version: u64,
            latest_checkpoint: &'a Option<OwnerCheckpoint>,
            highest_checkpoint_seq: u64,
            anchor_channel: &'a AnchorChannel,
            policy_version: u64,
            ownership_conflict: &'a Option<(AgentId, AgentId)>,
            last_history_endorser: &'a Option<AgentId>,
        }
        Ok(bincode::serialize(&View {
            id: &self.id,
            keys: self.keys.canonical_retained_wire(),
            entries: &self.entries,
            name: &self.name,
            policy: &self.policy,
            owner: &self.owner,
            allowed_writers: &self.allowed_writers,
            version: self.version,
            latest_checkpoint: &self.latest_checkpoint,
            highest_checkpoint_seq: self.highest_checkpoint_seq,
            anchor_channel: &self.anchor_channel,
            policy_version: self.policy_version,
            ownership_conflict: &self.ownership_conflict,
            last_history_endorser: &self.last_history_endorser,
        })?)
    }

    /// Test helper: the served image decoded back into a store.
    #[cfg(test)]
    pub(crate) fn served_image_for_test(&self) -> Self {
        bincode::deserialize(&self.encode_retained_image().expect("encode")).expect("decode")
    }

    /// #1970: the retained-image status of a group store; `None` for a
    /// store that does not serve a retained group image.
    #[must_use]
    pub fn image_status(&self) -> Option<ImageStatus> {
        if !self.serves_retained_group_image() {
            return None;
        }
        let image = self.retained_image_len().ok()?;
        Some(self.image.status(image, now_ms()))
    }

    /// #1970: whether this replica should pull from `source` now. After a
    /// refusal of `source`, pulls wait for its retry window unless the
    /// image has shrunk since. Never consulted for admission.
    #[must_use]
    pub fn image_retry_due(&self, source: &AgentId) -> bool {
        self.image.retry_due(source, now_ms())
    }

    /// A copy of this store without its entries, for [`Self::rollback`].
    /// The OR-Set is copied (tags only, no values): O(tags in the store).
    /// Image merges and snapshot adoption use it; their input is a whole
    /// image, so the merge itself is of that order too.
    fn snapshot_without_entries(&mut self) -> Rollback {
        #[cfg(test)]
        SNAPSHOTS.with(|n| n.set(n.get() + 1));
        let entries = std::mem::take(&mut self.entries);
        let snapshot = Box::new(self.clone());
        self.entries = entries;
        Rollback::Copy(snapshot)
    }

    /// Rollback state for a delta that touches only the OR-Set elements
    /// `touched` (#2146): a copy of this store without its entries and
    /// without its OR-Set, and an OR-Set undo log holding the slots of each
    /// touched key. Cost: O(touched keys and their tags + changelog
    /// entries); the caller compacts the changelog first, so it does not
    /// depend on the size of the store.
    ///
    /// Undo-log rule: the delta may change no OR-Set element outside
    /// `touched` before [`Self::rollback`] or before the log is dropped.
    /// [`Self::apply_delta_content`] changes only the keys of a delta's
    /// `added` and `removed`, and [`Self::settle_and_measure`] only
    /// compacts the changelog, which the undo log allows.
    fn snapshot_for_delta(&mut self, touched: &[String]) -> Rollback {
        let mut undo = self.keys.begin_undo();
        for key in touched {
            self.keys.save_for_undo(&mut undo, key);
        }
        #[cfg(test)]
        DELTA_UNDO_SAVES.with(|n| n.set(n.get() + undo.saved_len() as u64));
        let entries = std::mem::take(&mut self.entries);
        let keys = std::mem::take(&mut self.keys);
        let rest = Box::new(self.clone());
        self.entries = entries;
        self.keys = keys;
        Rollback::Undo(rest, undo)
    }

    /// Undo a merge: put back every entry `journal` saw change and every
    /// other field from `snapshot`. For [`Rollback::Undo`] the OR-Set is
    /// put back from its undo log.
    ///
    /// # Errors
    ///
    /// [`KvError::Merge`] when the OR-Set undo log does not come from this
    /// set (its version is later than the set's). That cannot happen on
    /// the delta path, which only moves the set's version forward; the
    /// error is reported rather than hidden.
    fn rollback(&mut self, snapshot: Rollback, journal: EntryJournal) -> Result<()> {
        for (key, prior) in journal.priors {
            match prior {
                EntryPrior::Absent => {
                    self.entries.remove(&key);
                }
                EntryPrior::Entry(entry) => {
                    self.entries.insert(key, entry);
                }
                EntryPrior::CreatedAt(created_at) => {
                    if let Some(entry) = self.entries.get_mut(&key) {
                        entry.created_at = created_at;
                    }
                }
            }
        }
        let entries = std::mem::take(&mut self.entries);
        match snapshot {
            Rollback::Copy(snapshot) => {
                *self = *snapshot;
                self.entries = entries;
                Ok(())
            }
            Rollback::Undo(rest, undo) => {
                let mut keys = std::mem::take(&mut self.keys);
                *self = *rest;
                self.entries = entries;
                let undone = keys.undo(undo);
                self.keys = keys;
                undone.map_err(|e| KvError::Merge(format!("OR-Set undo failed: {e}")))
            }
        }
    }

    /// #1970 admission rule, on a merge already applied in place and
    /// settled: keep it when the measured admission image is at most
    /// [`HARD_IMAGE_LIMIT_BYTES`]; else roll it back and record the refusal
    /// against `source`. `before` is the retained size before the merge;
    /// a kept merge that shrank the image re-opens every retry window.
    /// `content` is the exact content length after the merge when the
    /// caller kept it; `None` measures it.
    fn admit_or_rollback(
        &mut self,
        snapshot: Rollback,
        journal: EntryJournal,
        source: Option<AgentId>,
        before: u64,
        content: Option<u64>,
    ) -> Result<()> {
        let measured = content
            .map_or_else(|| self.content_len(), Ok)
            .and_then(|content| {
                Ok((
                    content,
                    self.admission_rest_len()?,
                    self.retained_with_content(content)?,
                ))
            });
        let (content, rest, retained) = match measured {
            Ok(sizes) => sizes,
            Err(e) => {
                self.rollback(snapshot, journal)?;
                return Err(e);
            }
        };
        let image = content.saturating_add(rest);
        if image > HARD_IMAGE_LIMIT_BYTES as u64 {
            self.rollback(snapshot, journal)?;
            return Err(self.refuse_merge(source, image, false));
        }
        self.image
            .set_content(self.version, self.keys.version(), content);
        if retained < before {
            self.image.rearm();
        }
        Ok(())
    }

    /// Record a refused merge against `source` and return its error.
    /// `lower_bound`: `image` is the pre-check's lower bound, not a measure.
    fn refuse_merge(&mut self, source: Option<AgentId>, image: u64, lower_bound: bool) -> KvError {
        let log = match source {
            Some(source) => self.image.note_refusal(source, image, now_ms()),
            None => true,
        };
        if log {
            tracing::warn!(
                store = %self.id,
                source = source.map(|s| hex::encode(s.as_bytes())).unwrap_or_default(),
                image,
                lower_bound,
                max = HARD_IMAGE_LIMIT_BYTES,
                "refused a merge: the merged retained image would pass the hard limit"
            );
        }
        KvError::StoreFull {
            image,
            max: HARD_IMAGE_LIMIT_BYTES,
        }
    }

    /// Merge `entry` into `key`'s entry with the one LWW rule, or insert it,
    /// recording what changed in `journal`.
    fn journal_merge_entry(&mut self, key: &str, entry: &KvEntry, journal: &mut EntryJournal) {
        match self.entries.get_mut(key) {
            Some(local) => match local.merge_tracked(entry) {
                MergePrior::Unchanged => {}
                MergePrior::CreatedAt(created_at) => {
                    journal.record(key, EntryPrior::CreatedAt(created_at));
                }
                MergePrior::Replaced(prior) => journal.record(key, EntryPrior::Entry(prior)),
            },
            None => {
                self.entries.insert(key.to_string(), entry.clone());
                journal.record(key, EntryPrior::Absent);
            }
        }
    }

    /// Remove `key`'s entry, recording it in `journal`.
    fn journal_remove_entry(&mut self, key: &str, journal: &mut EntryJournal) {
        if let Some(prior) = self.entries.remove(key) {
            journal.record(key, EntryPrior::Entry(prior));
        }
    }

    /// Test-only access to the raw entry map (#1094 P2 tests build an
    /// inconsistent store).
    #[cfg(test)]
    pub(crate) fn entries_mut_for_test(&mut self) -> &mut HashMap<String, KvEntry> {
        self.image.invalidate_content();
        &mut self.entries
    }

    /// #1094 P1: mark `key`'s current entry as written by the holder of
    /// `public_key`, with `rider` when a rider wrote through it. The store
    /// version does not move: call it in the same write lock as the put, so
    /// the mark is part of what that put publishes and commits.
    ///
    /// # Errors
    ///
    /// [`KvError::Merge`] when the key has no entry or signing fails.
    pub fn mark_entry_writer(
        &mut self,
        key: &str,
        public_key: &ant_quic::MlDsaPublicKey,
        secret_key: &ant_quic::MlDsaSecretKey,
        rider: Option<&str>,
    ) -> Result<()> {
        let id = *self.id();
        self.image.invalidate_content();
        let entry = self
            .entries
            .get_mut(key)
            .ok_or_else(|| KvError::Merge(format!("no entry to mark for key {key:?}")))?;
        crate::kv::provenance::mark(entry, &id, public_key, secret_key, rider)
            .map_err(KvError::Merge)
    }

    /// Get an entry by key.
    ///
    /// Gated on active-key membership so a tombstoned key never reads back.
    /// `entries` is not a reliable proxy for the active set: `merge` applies a
    /// remote OR-Set tombstone via `merge_state` without pruning `entries`, so
    /// a key can linger in `entries` after it leaves the active set. We query
    /// the OR-Set directly (an O(1) membership check) rather than materializing
    /// and linearly scanning `elements()` as the previous implementation did.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&KvEntry> {
        if self.keys.contains(&key.to_string()) {
            self.entries.get(key)
        } else {
            None
        }
    }

    /// Whether this replica holds an entry for `key`: the test
    /// [`Self::remove`] applies.
    pub(crate) fn holds_entry(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// Remove a key from the store.
    ///
    /// # Errors
    ///
    /// - [`KvError::KeyNotFound`] if the key does not exist.
    /// - [`KvError::ImmutableKey`] under [`AccessPolicy::AppendOnly`]: keys
    ///   can never be deleted, even by the owner.
    pub fn remove(&mut self, key: &str) -> Result<()> {
        if !self.holds_entry(key) {
            return Err(KvError::KeyNotFound(key.to_string()));
        }
        if matches!(self.policy, AccessPolicy::AppendOnly) {
            return Err(KvError::ImmutableKey(key.to_string()));
        }

        self.keys
            .remove(&key.to_string())
            .map_err(|e| KvError::Merge(format!("OR-Set remove failed: {e}")))?;
        self.entries.remove(key);
        if self.serves_retained_group_image() {
            self.keys.compact(0);
        }
        self.image.rearm();

        self.version += 1;
        Ok(())
    }

    /// List all active keys (not tombstoned).
    #[must_use]
    pub fn active_keys(&self) -> Vec<&String> {
        self.keys.elements().into_iter().collect()
    }

    /// List all active entries.
    #[must_use]
    pub fn active_entries(&self) -> Vec<&KvEntry> {
        let active: HashSet<String> = self.keys.elements().into_iter().cloned().collect();
        self.entries
            .values()
            .filter(|e| active.contains(&e.key))
            .collect()
    }

    /// Active entries paired with their outer map keys, for canonical
    /// checkpoint root computation. Borrows from `self` — no cloning.
    pub(crate) fn checkpoint_pairs(&self) -> Vec<(&str, &KvEntry)> {
        self.keys
            .elements()
            .into_iter()
            .filter_map(|k| self.entries.get(k).map(|e| (k.as_str(), e)))
            .collect()
    }

    /// Update the store name.
    pub fn update_name(&mut self, name: String, peer_id: PeerId) {
        self.name.set(name, peer_id);
        self.bump_version_keeping_content();
    }

    /// Move the store version for a change outside the content (OR-Set and
    /// entries), carrying a cached content length across it (#2110), so a
    /// remote owner announce cannot make the next delta measure the store.
    fn bump_version_keeping_content(&mut self) {
        let cached = self.image.cached_content(self.version, self.keys.version());
        self.version += 1;
        if let Some(content) = cached {
            self.image
                .set_content(self.version, self.keys.version(), content);
        }
    }

    // -----------------------------------------------------------------
    // SelfKeyed quota (issue #340) — deterministic lowest-N admission.
    // -----------------------------------------------------------------

    /// Candidate live `(key, value_len)` pairs for `writer`, overlaid with
    /// pending puts (`key -> NEW value_len`; an update of a live key counts
    /// the replacement value). Lexicographically sorted; foreign keys are
    /// never included.
    fn self_keyed_candidates(
        &self,
        writer: &AgentId,
        puts: &HashMap<String, u64>,
    ) -> Vec<(String, u64)> {
        let mut lens: HashMap<String, u64> = self
            .keys
            .elements()
            .into_iter()
            .filter(|k| key_agent_prefix(k) == Some(*writer))
            .map(|k| {
                (
                    k.clone(),
                    self.entries.get(k).map_or(0u64, |e| e.value.len() as u64),
                )
            })
            .collect();
        for (key, len) in puts {
            lens.insert(key.clone(), *len);
        }
        let mut candidates: Vec<(String, u64)> = lens.into_iter().collect();
        candidates.sort_by(|a, b| a.0.cmp(&b.0));
        candidates
    }

    /// Deterministic lowest-N admission (I7): admit candidates from the
    /// lexicographic front until the key-count or byte-total cap would be
    /// exceeded; everything from there on (the tail) is dropped. A pure
    /// function of the candidate set, so any two replicas with the same live
    /// set admit the same subset.
    fn self_keyed_admitted(candidates: &[(String, u64)]) -> HashSet<&str> {
        let mut admitted: HashSet<&str> = HashSet::new();
        let mut bytes = 0u64;
        for (key, len) in candidates {
            if admitted.len() >= MAX_SELFKEYED_KEYS_PER_AGENT
                || bytes.saturating_add(*len) > MAX_SELFKEYED_BYTES_PER_AGENT
            {
                break; // drop this candidate and the whole lexicographic tail
            }
            admitted.insert(key.as_str());
            bytes = bytes.saturating_add(*len);
        }
        admitted
    }

    /// Local-put quota predicate — the SAME rule the remote merge applies,
    /// so a local write that peers would drop never mutates this replica.
    fn check_self_keyed_admission(
        &self,
        writer: &AgentId,
        key: &str,
        value_len: usize,
    ) -> Result<()> {
        let mut puts = HashMap::new();
        puts.insert(key.to_string(), value_len as u64);
        let candidates = self.self_keyed_candidates(writer, &puts);
        let admitted = Self::self_keyed_admitted(&candidates);
        if admitted.contains(key) {
            return Ok(());
        }
        let bytes = candidates.iter().map(|(_, len)| len).sum();
        Err(KvError::AgentQuotaExceeded {
            agent: *writer,
            keys: candidates.len(),
            bytes,
            max_keys: MAX_SELFKEYED_KEYS_PER_AGENT,
            max_bytes: MAX_SELFKEYED_BYTES_PER_AGENT,
        })
    }

    /// Shared live-set enforcement (I7): evict `writer`'s live keys outside
    /// `admitted`. Both the remote merge (step 4 of
    /// [`merge_delta_self_keyed`](Self::merge_delta_self_keyed)) and the
    /// local put path call this, so neither side can hold keys the other
    /// drops. Returns the evicted keys, sorted.
    fn evict_outside_admitted(
        &mut self,
        writer: &AgentId,
        admitted: &HashSet<&str>,
    ) -> Vec<String> {
        let mut stale: Vec<String> = self
            .keys
            .elements()
            .into_iter()
            .filter(|k| key_agent_prefix(k) == Some(*writer) && !admitted.contains(k.as_str()))
            .cloned()
            .collect();
        for key in &stale {
            let _ = self.keys.remove(key);
            self.entries.remove(key);
        }
        stale.sort();
        stale
    }

    /// Enforce the `SelfKeyed` live-set cap after a LOCAL put of a key bound
    /// to `writer` — the same predicate as the remote merge's step 4,
    /// recomputed over the post-put live set. [`authorize_put`](Self::authorize_put)
    /// only gates the incoming key; without this the local replica could
    /// hold 65 keys while every remote holds the admitted 64.
    ///
    /// Returns the evicted keys, sorted.
    fn enforce_self_keyed_live_set(&mut self, writer: &AgentId) -> Vec<String> {
        let candidates = self.self_keyed_candidates(writer, &HashMap::new());
        let admitted = Self::self_keyed_admitted(&candidates);
        self.evict_outside_admitted(writer, &admitted)
    }

    /// `AccessPolicy::SelfKeyed` merge path (issue #340).
    ///
    /// Per-key authority instead of a whole-delta owner gate: the gossip
    /// envelope's verified `msg.sender` (passed as `writer`) is the only
    /// identity, and a writer can only touch keys bound to its own prefix
    /// (I1). Anonymous deltas apply NOTHING (I5). Encrypted is independently
    /// fail-closed (#358); SelfKeyed does not share that path.
    ///
    /// Order: the writer's own tombstones first (they free quota budget),
    /// then own adds/updates admitted by the deterministic lowest-N rule,
    /// then eviction of the writer's live keys outside the admitted set (the
    /// quota is a hard cap on the live set, so replicas fed in different
    /// orders converge on the same subset — I7). Foreign keys in
    /// `added`/`updated`/`removed` are skipped (I6). Allowlist mutations and
    /// any carried owner checkpoint are ignored (I8 — this store has no
    /// owner and never publishes or adopts checkpoints).
    fn merge_delta_self_keyed(
        &mut self,
        delta: &KvStoreDelta,
        writer: Option<&AgentId>,
    ) -> Result<()> {
        let Some(w) = writer else {
            tracing::warn!("rejected anonymous self_keyed delta for store {}", self.id);
            return Ok(()); // silent whole-delta reject — applies nothing
        };
        if delta_has_inconsistent_entry(delta) {
            tracing::warn!(
                "rejected self_keyed delta for store {}: an entry is not under its own key or does not match its hash",
                self.id
            );
            return Ok(());
        }
        // Ambiguity gate (mirrors the sender-auth path): a delta carrying the
        // same key in both `added` and `updated` is ambiguous by
        // construction — drop the whole delta.
        for key in delta.updated.keys() {
            if delta.added.contains_key(key) {
                tracing::warn!(
                    "rejected ambiguous self_keyed delta for store {}: key {key:?} appears in both added and updated",
                    self.id
                );
                return Ok(());
            }
        }
        // 1. The writer's own tombstones first — a single delta can free
        //    budget and spend it (apply-order guarantee).
        for key in delta.removed.keys() {
            if key_agent_prefix(key) != Some(*w) {
                continue; // foreign tombstone: skipped (I6)
            }
            let _ = self.keys.remove(key);
            self.entries.remove(key);
        }
        // 2. Collect the writer's otherwise-admissible puts (prefix-bound
        //    keys only; foreign keys are skipped).
        let mut puts: HashMap<String, u64> = HashMap::new();
        for (key, (entry, _tag)) in &delta.added {
            if key_agent_prefix(key) == Some(*w) {
                puts.insert(key.clone(), entry.value.len() as u64);
            }
        }
        // An update of a key that is not live here adds nothing, so it must
        // not take a quota slot from a live key (#2068 point 2).
        for (key, entry) in &delta.updated {
            if key_agent_prefix(key) == Some(*w) && self.keys.contains(key) {
                puts.insert(key.clone(), entry.value.len() as u64);
            }
        }
        // 3. Deterministic lowest-N admission over survivors ∪ own puts.
        //    `admitted` contains only the writer's own keys, so foreign puts
        //    fail the membership check below and are skipped.
        let candidates = self.self_keyed_candidates(w, &puts);
        let admitted = Self::self_keyed_admitted(&candidates);
        for (key, (entry, tag)) in &delta.added {
            if !admitted.contains(key.as_str()) {
                continue; // foreign key or over-quota tail: skipped
            }
            self.keys
                .add(key.clone(), *tag)
                .map_err(|e| KvError::Merge(format!("OR-Set add failed: {e}")))?;
            if let Some(existing) = self.entries.get_mut(key) {
                existing.merge(entry);
            } else {
                self.entries.insert(key.clone(), entry.clone());
            }
        }
        for (key, entry) in &delta.updated {
            if !admitted.contains(key.as_str()) || !self.keys.contains(key) {
                continue;
            }
            if let Some(existing) = self.entries.get_mut(key) {
                existing.merge(entry);
            } else {
                self.entries.insert(key.clone(), entry.clone());
            }
        }
        // 4. Evict the writer's live keys outside the admitted set: the
        //    admitted set is a pure function of the candidate live set, so
        //    every replica converges to exactly that subset regardless of
        //    delivery order (I7). Shared with the local put path
        //    (`enforce_self_keyed_live_set`) so neither side can hold keys
        //    the other drops.
        let evicted = self.evict_outside_admitted(w, &admitted);
        if !evicted.is_empty() {
            tracing::debug!(
                evicted = evicted.len(),
                "self_keyed merge evicted writer keys outside the lowest-N admitted set"
            );
        }
        // The name is LWW metadata, not directory content — merge it like
        // every other policy so replicas converge on the creator's name.
        if let Some(name_register) = &delta.name_update {
            self.name.merge(name_register);
        }
        self.version += 1;
        Ok(())
    }

    /// Merge a delta into this store.
    ///
    /// Enforces access control: if the store has a Signed or Allowlisted
    /// policy, the `writer` must be authorized. Unauthorized, ambiguous and
    /// inconsistent deltas are rejected without applying changes (returning
    /// `Ok` with a rejected outcome, not an error). On a store that serves
    /// its complete state as a retained group image (#1970), a delta whose
    /// merge would grow the canonical retained image past the
    /// retained-image limit is refused typed before any of it applies; a
    /// delta that does not grow it past the limit — a removal, a
    /// same-size overwrite, a re-delivery — merges, so an over-limit
    /// store can still recover.
    ///
    /// # Errors
    ///
    /// [`KvError::StoreFull`] when the merged image would grow past the
    /// retained-image limit (retained-image stores only); [`KvError::Merge`]
    /// or [`KvError::Serialization`] when applying the admitted content
    /// fails.
    pub fn merge_delta(
        &mut self,
        delta: &KvStoreDelta,
        peer_id: PeerId,
        writer: Option<&AgentId>,
    ) -> Result<()> {
        self.merge_delta_with_outcome(delta, peer_id, writer)
            .map(|_| ())
    }

    /// Merge and report whether the input passed the admission gates. The caller
    /// must hold the same store lock through any dependent destructive action.
    pub(crate) fn merge_delta_with_outcome(
        &mut self,
        delta: &KvStoreDelta,
        peer_id: PeerId,
        writer: Option<&AgentId>,
    ) -> Result<MergeOutcome> {
        self.merge_delta_with_outcome_inner(delta, peer_id, writer, false)
    }

    /// Merge an encrypted delta while the caller holds this store's write
    /// guard and the attached GSS context's authorization read guard. This
    /// skips only the duplicate writer lookup, which would recursively take
    /// the context read lock and can deadlock behind a waiting updater.
    pub(crate) fn merge_guarded_encrypted_delta(
        &mut self,
        delta: &KvStoreDelta,
        peer_id: PeerId,
        writer: &AgentId,
        verified_context: &Arc<dyn KvSecureContext>,
    ) -> Result<MergeOutcome> {
        if !matches!(self.policy, AccessPolicy::Encrypted { .. })
            || !self
                .secure
                .as_ref()
                .is_some_and(|attached| Arc::ptr_eq(attached, verified_context))
        {
            return Err(KvError::Unauthorized(
                "guarded encrypted merge requires its attached secure context".to_string(),
            ));
        }
        self.merge_delta_with_outcome_inner(delta, peer_id, Some(writer), true)
    }

    fn merge_delta_with_outcome_inner(
        &mut self,
        delta: &KvStoreDelta,
        peer_id: PeerId,
        writer: Option<&AgentId>,
        writer_pre_authorized: bool,
    ) -> Result<MergeOutcome> {
        // SelfKeyed directories take the per-key path: no owner gate, no
        // checkpoint adoption — the store has no owner for life (I3/I8), so
        // both owner-anchored blocks below would no-op anyway.
        if matches!(self.policy, AccessPolicy::SelfKeyed) {
            return self
                .merge_delta_self_keyed(delta, writer)
                .map(|()| MergeOutcome::Applied);
        }
        // GroupSigned authority is anchored exclusively in the canonical
        // group roster and policy attached through `secure`. A signed delta
        // from a current writer may mutate content, but it must never relay
        // the ordinary owner-checkpoint/name/allowlist authority used by
        // owner-anchored stores. In particular, checkpoint adoption is a
        // full replacement and copies `cp.policy`; allowing it here would
        // discard concurrent group writes and could downgrade GroupSigned.
        if matches!(self.policy, AccessPolicy::GroupSigned { .. })
            && (delta.owner_checkpoint.is_some()
                || delta.name_update.is_some()
                || delta.allowlist_additions.is_some()
                || delta.allowlist_removals.is_some())
        {
            tracing::warn!(
                "rejected group-signed delta carrying non-content authority for store {}",
                self.id
            );
            return Ok(MergeOutcome::Rejected(MergeRejection::GroupSignedAuthority));
        }
        // Authoritative full-snapshot checkpoint adoption (cold-recovery path):
        // if the checkpoint's content root matches the relayed entry set, adopt
        // as owner-proven independent of the relayer. An incremental delta's
        // single-entry set won't match a full-state root, so it falls through
        // to the sender-auth path below (where the owner is authorized as
        // writer==owner), and the checkpoint is cached afterward by
        // maybe_cache_checkpoint if the resulting state matches.
        if let Some(cp) = delta.owner_checkpoint.as_ref() {
            if self.try_adopt_full_snapshot(delta, peer_id, cp)? {
                return Ok(MergeOutcome::Applied);
            }
            // Stale-delta gate: a delta carrying a genuine owner checkpoint
            // at or below the adopted high-water mark was published at or
            // before the adopted checkpoint's state, so its mutations are
            // already reflected in (or superseded by) that full snapshot.
            // Without this gate the gossip replay/cache window re-delivers
            // old owner-signed incremental deltas after a cold-recovery
            // checkpoint adoption, and the sender-auth path below re-adds
            // owner-DELETED keys on a fresh joiner (which holds no OR-Set
            // tombstones for them) — resurrecting deleted state.
            if self.is_subsumed_by_adopted_checkpoint(cp) {
                tracing::debug!(
                    "dropped stale owner delta (checkpoint_seq {} <= adopted {}) for store {}",
                    cp.checkpoint_seq,
                    self.highest_checkpoint_seq,
                    self.id
                );
                return Ok(MergeOutcome::SubsumedCheckpoint);
            }
        }
        // Access control: reject unauthorized writes
        if let Some(writer_id) = writer {
            if !writer_pre_authorized && !self.is_authorized(writer_id) {
                tracing::warn!(
                    "rejected delta from unauthorized writer {} for store {}",
                    hex::encode(writer_id.as_bytes()),
                    self.id
                );
                return Ok(MergeOutcome::Rejected(MergeRejection::UnauthorizedWriter));
            }
        } else {
            // No writer identity applies nothing under ANY policy: the
            // gossip V2 envelope supplies the verified sender for
            // Signed/Allowlisted/AppendOnly merges, and the reserved
            // Encrypted policy is fail-closed (#341 Phase A) until secure
            // sync is wired — it is no longer an anonymous-merge escape
            // hatch.
            tracing::warn!("rejected anonymous delta for store {}", self.id);
            return Ok(MergeOutcome::Rejected(MergeRejection::AnonymousWriter));
        }

        // Canonical-map gate, ALL policies: a delta carrying the same key in
        // both `added` and `updated` is ambiguous by construction (two values
        // for one key in one message) — no legitimate producer emits it
        // (`for_put` is added-only, removals are removed-only, `full_delta`
        // is added-only). Drop the whole delta rather than letting map
        // iteration/LWW order decide which copy wins. Mirrors the adoption
        // path's 5b gate; only the authorized writer can reach this point,
        // so rejection cannot be used by third parties to censor writes.
        for key in delta.updated.keys() {
            if delta.added.contains_key(key) {
                tracing::warn!(
                    "rejected ambiguous delta for store {}: key {key:?} appears in both added and updated",
                    self.id
                );
                return Ok(MergeOutcome::Rejected(MergeRejection::AmbiguousDelta));
            }
        }
        // Entry gate, ALL policies (#1094 P1/P2, reviews of #1963): an entry
        // must sit under its own key and match its content hash. Otherwise
        // one key's value and writer mark could be shown under another key,
        // or two replicas could hold different bytes under one LWW identity.
        // No legitimate producer emits it.
        if delta_has_inconsistent_entry(delta) {
            tracing::warn!(
                "rejected delta for store {}: an entry is not under its own key or does not match its hash",
                self.id
            );
            return Ok(MergeOutcome::Rejected(MergeRejection::InconsistentEntry));
        }

        if self.serves_retained_group_image() {
            return self.merge_delta_bounded(delta, writer);
        }
        self.apply_delta_content(delta, writer, &mut EntryJournal::default())
    }

    /// #1970: merge `delta` under the admission rule: it is kept only when
    /// the measured merged image (replicated part plus the local allowance)
    /// is at most
    /// [`HARD_IMAGE_LIMIT_BYTES`]. Every delta is measured; nothing is
    /// refused on a bound or a back-off alone.
    ///
    /// The cached content length is exact, and every delta changes it by
    /// the exact change in its touched keys' OR-Set slots and entries, so
    /// while it is cached the measure is O(keys in the delta) (#2110). A
    /// local put, remove or writer mark, or a load, drops it; the next delta
    /// measures it once. When an upper growth bound fits, the delta just
    /// applies. Otherwise a lower bound over the limit refuses it unapplied;
    /// else it applies in place under an entry journal and an OR-Set undo
    /// log of its touched keys, and is kept or rolled back. No step copies
    /// the whole OR-Set (#2146).
    ///
    /// # Errors
    ///
    /// [`KvError::StoreFull`] when the merged image would pass the hard
    /// limit; nothing is applied. [`KvError::Serialization`] when a measure
    /// fails, plus whatever applying the delta raises.
    fn merge_delta_bounded(
        &mut self,
        delta: &KvStoreDelta,
        writer: Option<&AgentId>,
    ) -> Result<MergeOutcome> {
        let outcome = self.merge_delta_bounded_inner(delta, writer)?;
        // A removal from `writer` can shrink the writer's own image even when
        // this replica held none of the removed keys, so the writer's
        // deferred pull is retried now (#2068 point 4).
        if !delta.removed.is_empty() {
            if let Some(source) = writer {
                self.image.rearm_source(source, now_ms());
            }
        }
        Ok(outcome)
    }

    fn merge_delta_bounded_inner(
        &mut self,
        delta: &KvStoreDelta,
        writer: Option<&AgentId>,
    ) -> Result<MergeOutcome> {
        let touched: Vec<String> = delta
            .added
            .keys()
            .chain(delta.removed.keys())
            .chain(delta.updated.keys())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .cloned()
            .collect();
        // No key cap: every ingress path decodes a delta under a 4 MiB
        // limit (`gossip::wire::decode_delta` for plain and sealed records,
        // 64 KiB DM envelopes), which bounds a delta to about 250 000
        // removals or 25 000 entries, and the work below is O(touched keys).
        let (keys_growth, entries_growth, rest_growth) = self.delta_growth_bound(delta)?;
        let content = self.content_exact()?;
        let bound = content
            .saturating_add(keys_growth)
            .saturating_add(entries_growth)
            .saturating_add(self.admission_rest_len()?)
            .saturating_add(rest_growth);
        let orset_before: i128 = touched
            .iter()
            .map(|key| i128::from(self.orset_key_len(key)))
            .sum();
        let mut journal = EntryJournal::default();
        if bound <= HARD_IMAGE_LIMIT_BYTES as u64 {
            let outcome = self.apply_delta_content(delta, writer, &mut journal)?;
            let (change, after) =
                self.settle_and_measure(content, &touched, orset_before, &mut journal);
            self.image
                .set_content(self.version, self.keys.version(), after);
            if change < 0 {
                self.image.rearm();
            }
            return Ok(outcome);
        }
        let lowest = i128::from(content) + self.delta_lowest_growth(delta, &touched)?;
        if lowest > i128::from(HARD_IMAGE_LIMIT_BYTES as u64) {
            let image = u64::try_from(lowest).unwrap_or(u64::MAX);
            return Err(self.refuse_merge(writer.copied(), image, true));
        }
        let before = self.retained_with_content(content)?;
        // `content_exact` compacted the changelog, so the undo log copies
        // no changelog and costs O(touched keys) (#2146).
        let snapshot = self.snapshot_for_delta(&touched);
        let outcome = match self.apply_delta_content(delta, writer, &mut journal) {
            Ok(outcome) => outcome,
            Err(e) => {
                self.rollback(snapshot, journal)?;
                return Err(e);
            }
        };
        let (_, after) = self.settle_and_measure(content, &touched, orset_before, &mut journal);
        self.admit_or_rollback(snapshot, journal, writer.copied(), before, Some(after))?;
        Ok(outcome)
    }

    /// Settle the keys a delta touched and return the exact change in
    /// content bytes (each touched key's OR-Set slots and entry, before and
    /// after) with the content length `content` becomes. Settling empties
    /// the OR-Set changelog, so the OR-Set encoding is the sum of its key
    /// slots again.
    fn settle_and_measure(
        &mut self,
        content: u64,
        touched: &[String],
        orset_before: i128,
        journal: &mut EntryJournal,
    ) -> (i128, u64) {
        self.settle_retained(Some(touched), journal);
        let orset_after: i128 = touched
            .iter()
            .map(|key| i128::from(self.orset_key_len(key)))
            .sum();
        let change = orset_after - orset_before + self.journal_entry_delta(journal);
        let after = i128::from(content) + change;
        debug_assert!(after >= 0, "content {content} changed by {change}");
        (change, after.max(0) as u64)
    }

    /// Apply an admitted delta's content and authority: allowlist changes,
    /// added, removed and updated entries, the name register, the cached
    /// checkpoint and the version bump. Callers have already run the
    /// admission gates (authorization, ambiguity, integrity and, for
    /// retained-image stores, the #1970 size bound).
    fn apply_delta_content(
        &mut self,
        delta: &KvStoreDelta,
        writer: Option<&AgentId>,
        journal: &mut EntryJournal,
    ) -> Result<MergeOutcome> {
        // Apply allowlist changes from the delta (owner-only)
        if let Some(ref additions) = delta.allowlist_additions {
            if writer.is_some_and(|w| self.owner.as_ref().is_some_and(|o| o == w)) {
                for agent in additions {
                    self.allowed_writers.insert(*agent);
                }
            }
        }
        if let Some(ref removals) = delta.allowlist_removals {
            if writer.is_some_and(|w| self.owner.as_ref().is_some_and(|o| o == w)) {
                for agent in removals {
                    self.allowed_writers.remove(agent);
                }
            }
        }

        // Apply added entries
        for (key, (entry, tag)) in &delta.added {
            if self.append_only_rejects_entry(key, entry) {
                continue; // skip this entry; the rest of the delta still applies
            }
            self.keys
                .add(key.clone(), *tag)
                .map_err(|e| KvError::Merge(format!("OR-Set add failed: {e}")))?;
            self.journal_merge_entry(key, entry, journal);
        }

        // Apply removed keys — never for AppendOnly stores: keys are immutable
        // and cannot be removed, even by an owner-signed delta (an owner
        // retroactively deleting records is exactly the attack AppendOnly
        // exists to stop).
        if matches!(self.policy, AccessPolicy::AppendOnly) {
            if !delta.removed.is_empty() {
                tracing::warn!(
                    "append-only violation: skipped {} remote key removal(s) for store {}",
                    delta.removed.len(),
                    self.id
                );
            }
        } else {
            for key in delta.removed.keys() {
                let _ = self.keys.remove(&key.to_string());
                self.journal_remove_entry(key, journal);
            }
        }

        // Apply updated entries. An update carries no OR-Set tag, so it only
        // merges into a live key: for a key this replica does not hold live
        // (never added, or removed, an image tombstone included) it is
        // skipped. Adding a tag here would bring a removed key back (#2068
        // point 2).
        for (key, entry) in &delta.updated {
            if self.append_only_rejects_entry(key, entry) || !self.keys.contains(key) {
                continue; // skip this entry; the rest of the delta still applies
            }
            self.journal_merge_entry(key, entry, journal);
        }

        // Apply name update via LWW (vector-clock) merge so a stale delta
        // cannot overwrite a newer local name; mirrors the full-state merge.
        if let Some(ref name_register) = delta.name_update {
            self.name.merge(name_register);
        }
        // After an incremental mutation, cache the checkpoint if the resulting
        // complete state matches the checkpoint's content root. This ensures a
        // relay always carries the latest checkpoint after normal
        // multi-write/update/delete operations, so a fresh anchored joiner can
        // cold-recover the exact final state from a non-owner relay.
        if let Some(cp) = delta.owner_checkpoint.as_ref() {
            self.maybe_cache_checkpoint(cp);
        }

        self.version += 1;
        Ok(MergeOutcome::Applied)
    }

    /// AppendOnly guard for one incoming delta entry.
    ///
    /// `true` when this store is [`AccessPolicy::AppendOnly`] and `key` is
    /// already active locally — the incoming entry must be skipped WHOLESALE.
    /// Existing entries are frozen in full (value, content type, metadata,
    /// timestamps, content hash): even a byte-identical redelivery is not
    /// merged, because [`KvEntry::merge`] resolves by LWW timestamp and could
    /// otherwise mutate `metadata`/`updated_at` while the value stays equal.
    /// Owner-signed deltas are NOT exempt: an owner retroactively rewriting
    /// records is exactly the attack this policy exists to stop. Only a
    /// content-differing skip is warn-logged; an identical redelivery is a
    /// silent idempotent no-op.
    fn append_only_rejects_entry(&self, key: &str, entry: &KvEntry) -> bool {
        if !matches!(self.policy, AccessPolicy::AppendOnly) {
            return false;
        }
        let Some(local) = self.get(key) else {
            return false; // new key — a legitimate append
        };
        if !entry_frozen_fields_equal(local, entry) {
            tracing::warn!(
                "append-only violation: skipped remote update of existing key {key:?} for store {}",
                self.id
            );
        }
        true
    }

    /// Try to adopt an owner-signed checkpoint as an authoritative full
    /// snapshot.
    ///
    /// Returns `true` only when the checkpoint fully validates AND its content
    /// root matches the delta's relayed entry set (a full-state relay). Every
    /// relayed entry is independently integrity-checked (`outer_key ==
    /// entry.key`, `content_hash == blake3(value)`) before any mutation.
    /// Removals/tombstones are applied, the checkpoint is cached, and the
    /// high-water mark is updated. This is what lets an anchored joiner
    /// cold-recover a Signed store from a non-owner replica while the owner is
    /// offline.
    ///
    /// Returns `false` otherwise (unanchored, reserved Encrypted policy,
    /// bad sig/owner, stale seq, cross-store, entry integrity failure,
    /// root mismatch / incremental delta / tamper), in which case
    /// [`merge_delta`] falls through to the normal sender-auth path. Never
    /// establishes ownership (anchor gate).
    fn try_adopt_full_snapshot(
        &mut self,
        delta: &KvStoreDelta,
        peer_id: PeerId,
        cp: &OwnerCheckpoint,
    ) -> Result<bool> {
        if !self.full_snapshot_adoptable(delta, cp) {
            return Ok(false);
        }
        let mut journal = EntryJournal::default();
        if !self.serves_retained_group_image() {
            self.apply_full_snapshot(delta, peer_id, cp, &mut journal);
            return Ok(true);
        }
        // #1970: adoption is a merge into the retained image, so it is under
        // the same admission rule as deltas and retained images.
        let before = self.retained_image_len()?;
        let snapshot = self.snapshot_without_entries();
        self.apply_full_snapshot(delta, peer_id, cp, &mut journal);
        self.settle_retained(None, &mut journal);
        self.admit_or_rollback(snapshot, journal, self.owner, before, None)?;
        Ok(true)
    }

    /// Steps 0 to 6c of [`Self::try_adopt_full_snapshot`]: whether `cp`
    /// and the relayed entry set of `delta` may be adopted.
    fn full_snapshot_adoptable(&self, delta: &KvStoreDelta, cp: &OwnerCheckpoint) -> bool {
        // 0. Encrypted policy WITHOUT an attached secure context is
        //    fail-closed (#341 Phase A, I1): this path runs in merge_delta
        //    BEFORE the sender-auth check, so without this gate a genuine
        //    owner checkpoint would apply its plaintext entries and refresh
        //    the policy in step 10 — flipping the replica Encrypted→Signed
        //    and re-opening every write path. WITH a context (#341 Phase B)
        //    the record arrived sealed and author-verified through the
        //    encrypted sync path, so the ordinary gates below (anchor,
        //    signature, store binding, sequence, integrity, root) apply —
        //    the checkpoint author's membership was already enforced by the
        //    sync layer before merge.
        if let AccessPolicy::Encrypted { group_id } | AccessPolicy::TreeKemEncrypted { group_id } =
            &self.policy
        {
            if self.secure.is_none() {
                tracing::warn!(
                    target: "x0x::kv",
                    "rejected owner checkpoint for encrypted store {} (group_id {}) — no secure context attached; secure sync is not wired",
                    self.id,
                    hex::encode(group_id)
                );
                return false;
            }
        }
        // 1. Anchor gate: never learn the owner from a relay.
        let Some(expected_owner) = self.owner else {
            tracing::warn!("rejected owner checkpoint for unanchored store {}", self.id);
            return false;
        };
        // 2. Owner binding + signature.
        if let Err(e) = cp.verify(&expected_owner) {
            tracing::warn!("rejected owner checkpoint for store {}: {e}", self.id);
            return false;
        }
        // 3. Store/topic binding — store_id = for_topic_owner(topic, owner)
        //    binds both, and the signature covers topic + store_id, so a
        //    cross-store replay either mismatches the id or fails verification.
        if cp.store_id != self.id {
            tracing::warn!(
                "rejected owner checkpoint: store_id mismatch for {}",
                self.id
            );
            return false;
        }
        // 4. Replay/downgrade gate (monotonic checkpoint sequence).
        if cp.checkpoint_seq <= self.highest_checkpoint_seq {
            return false; // stale replay — ignore, fall through
        }
        // 5. Validate every relayed entry's integrity before any mutation.
        //    Fail-closed: a single malformed/inconsistent entry rejects the
        //    entire checkpoint adoption.
        for (key, (entry, _)) in &delta.added {
            if let Err(e) = validate_entry_integrity(key, entry) {
                tracing::warn!("rejected checkpoint entry for store {}: {e}", self.id);
                return false;
            }
        }
        for (key, entry) in &delta.updated {
            if let Err(e) = validate_entry_integrity(key, entry) {
                tracing::warn!("rejected checkpoint entry for store {}: {e}", self.id);
                return false;
            }
        }
        // 5b. Canonical-map gate: `added` and `updated` must be DISJOINT on
        //     the adoption path. No legitimate producer emits the same key in
        //     both maps of a full-state relay (`full_delta` populates only
        //     `added`; incremental owner deltas are single-map), but a crafted
        //     delta could carry key K in both with different values — the
        //     validation/root pass would see one set while adoption applies
        //     both maps in sequence, letting the second silently rewrite what
        //     was validated. Reject for ALL policies: adoption is a
        //     security-critical full-replace and an ambiguous multiset is
        //     tamper by construction. Fall-through to sender-auth is safe —
        //     its loops re-check state sequentially per entry.
        for key in delta.updated.keys() {
            if delta.added.contains_key(key) {
                tracing::warn!(
                    "rejected owner checkpoint for store {}: key {key:?} appears in both added and updated",
                    self.id
                );
                return false;
            }
        }
        // 6. Content integrity: the canonical root over the relayed entry set
        //    must match. This only holds for a full-state relay; an incremental
        //    delta's single entry set won't match a full-state checkpoint root,
        //    so the checkpoint doesn't apply and we fall through to sender-auth.
        let mut relayed: Vec<(&str, &KvEntry)> = delta
            .added
            .iter()
            .map(|(k, (e, _))| (k.as_str(), e))
            .collect();
        relayed.extend(delta.updated.iter().map(|(k, e)| (k.as_str(), e)));
        let relayed_name: &str = delta
            .name_update
            .as_ref()
            .map(|r| r.get().as_str())
            .unwrap_or("");
        if content_root(&self.id, relayed_name, &relayed) != cp.content_root {
            return false; // tamper / truncation / subset / incremental — fall through
        }
        // 6b. AppendOnly immutability gate: a checkpoint may only EXTEND the
        //     keyset. If adopting it would drop a locally-present key or
        //     change its bytes, reject the whole checkpoint and keep local
        //     state (fail loud) — an owner signing a rewritten/truncated
        //     history is exactly the attack AppendOnly exists to stop. A
        //     fresh joiner holds no local keys, so cold-start adoption is
        //     unaffected. Checked against BOTH the local policy and the
        //     checkpoint's claimed policy, so a hostile checkpoint cannot
        //     dodge the gate by flipping its own policy field.
        // AppendOnly is TERMINAL: a checkpoint claiming the store is no
        // longer append-only, presented to a replica that knows it is, is
        // hostile by definition (adopting it would downgrade the policy in
        // step 10 and unfreeze the log). Reject the whole checkpoint.
        if matches!(self.policy, AccessPolicy::AppendOnly)
            && !matches!(cp.policy, AccessPolicy::AppendOnly)
        {
            tracing::warn!(
                "append-only violation: rejected owner checkpoint seq {} for store {} — it downgrades the terminal append_only policy to {}",
                cp.checkpoint_seq,
                self.id,
                cp.policy
            );
            return false;
        }
        // 6c. Encrypted is TERMINAL (#341 Phase B): a checkpoint claiming the
        //     store is no longer group-encrypted (or is bound to a DIFFERENT
        //     group) is hostile by definition on an encrypted replica —
        //     adopting it would downgrade the policy in step 10 and move the
        //     store back onto plaintext paths. Reject the whole checkpoint.
        if let AccessPolicy::Encrypted {
            group_id: anchored_group,
        } = &self.policy
        {
            let keeps_binding = matches!(&cp.policy, AccessPolicy::Encrypted { group_id } if group_id == anchored_group);
            if !keeps_binding {
                tracing::warn!(
                    "encrypted violation: rejected owner checkpoint seq {} for store {} — it downgrades the terminal encrypted policy to {}",
                    cp.checkpoint_seq,
                    self.id,
                    cp.policy
                );
                return false;
            }
        }
        if let AccessPolicy::TreeKemEncrypted {
            group_id: anchored_group,
        } = &self.policy
        {
            let keeps_binding = matches!(&cp.policy, AccessPolicy::TreeKemEncrypted { group_id } if group_id == anchored_group);
            if !keeps_binding {
                return false;
            }
        }
        if matches!(self.policy, AccessPolicy::AppendOnly)
            || matches!(cp.policy, AccessPolicy::AppendOnly)
        {
            let signed_entries: HashMap<&str, &KvEntry> =
                relayed.iter().map(|(k, e)| (*k, *e)).collect();
            for key in self.keys.elements() {
                let Some(local) = self.entries.get(key) else {
                    continue;
                };
                match signed_entries.get(key.as_str()) {
                    None => {
                        tracing::warn!(
                            "append-only violation: rejected owner checkpoint seq {} for store {} — it drops existing key {key:?}",
                            cp.checkpoint_seq,
                            self.id
                        );
                        return false;
                    }
                    Some(remote) if !entry_frozen_fields_equal(remote, local) => {
                        tracing::warn!(
                            "append-only violation: rejected owner checkpoint seq {} for store {} — it rewrites existing key {key:?}",
                            cp.checkpoint_seq,
                            self.id
                        );
                        return false;
                    }
                    _ => {}
                }
            }
        }
        true
    }

    /// Steps 7 to 10 of [`Self::try_adopt_full_snapshot`], recording entry
    /// changes in `journal`.
    fn apply_full_snapshot(
        &mut self,
        delta: &KvStoreDelta,
        peer_id: PeerId,
        cp: &OwnerCheckpoint,
        journal: &mut EntryJournal,
    ) {
        // 7. Adopt: merge the entries as owner-authorized (bypass sender-auth).
        for (key, (entry, tag)) in &delta.added {
            let _ = self.keys.add(key.clone(), *tag);
            self.journal_merge_entry(key, entry, journal);
        }
        for (key, entry) in &delta.updated {
            if !self.entries.contains_key(key) {
                let _ = self.keys.add(key.clone(), (peer_id, 0));
            }
            self.journal_merge_entry(key, entry, journal);
        }
        // 8. Full-replace to the owner-signed set. Step 6 proved the relayed
        //    (added ∪ updated) keys ARE the owner's complete signed state, so
        //    the store's state after adoption must be EXACTLY that set. Drop any
        //    local key not in it — that reflects owner deletions on a
        //    cold-recovering joiner WITHOUT trusting the untrusted `delta.removed`
        //    field. This is the authoritative full-replace: a relay-injected
        //    `removed` cannot truncate (it is ignored; the signed set wins), and
        //    a relay cannot resurrect or hide keys (a stale/mismatched relayed
        //    set fails step 6 and never reaches here). `delta.removed` is
        //    deliberately NOT consulted on the checkpoint-adopt path.
        let signed_keys: std::collections::HashSet<&str> = delta
            .added
            .keys()
            .map(String::as_str)
            .chain(delta.updated.keys().map(String::as_str))
            .collect();
        let stale: Vec<String> = self
            .keys
            .elements()
            .into_iter()
            .filter(|k| !signed_keys.contains(k.as_str()))
            .cloned()
            .collect();
        for key in stale {
            let _ = self.keys.remove(&key);
            self.journal_remove_entry(&key, journal);
        }
        // 9. Apply name update.
        if let Some(name_register) = &delta.name_update {
            self.name.merge(name_register);
        }
        // 10. Refresh policy (forward only) and cache the checkpoint.
        //     Belt-and-braces: AppendOnly is terminal — the 6b gate already
        //     rejected any checkpoint that would downgrade it, so this branch
        //     can only keep or adopt AppendOnly, never leave it.
        //     Step 7 MERGES (one LWW rule, A10): a local entry or name later
        //     than the signed one wins, so the local state can differ from
        //     the checkpoint. The checkpoint is cached only when the root over
        //     the local state still matches it; otherwise no checkpoint is
        //     cached, so `full_delta` never relays a checkpoint that does not
        //     match the entries beside it (a receiver then takes the
        //     sender-auth path). The high-water mark still advances: the
        //     signed set was adopted.
        let downgrades_terminal_policy = matches!(self.policy, AccessPolicy::AppendOnly)
            && !matches!(cp.policy, AccessPolicy::AppendOnly);
        if cp.policy_version >= self.policy_version && !downgrades_terminal_policy {
            self.policy = cp.policy.clone();
            self.policy_version = cp.policy_version;
        }
        self.latest_checkpoint = self.local_root_matches(cp).then(|| cp.clone());
        self.highest_checkpoint_seq = cp.checkpoint_seq;
        self.version += 1;
    }

    /// Does the content root over this replica's complete state (entries
    /// and name) equal `cp`'s?
    fn local_root_matches(&self, cp: &OwnerCheckpoint) -> bool {
        content_root(&self.id, self.name(), &self.checkpoint_pairs()) == cp.content_root
    }

    /// True when `cp` is a genuine checkpoint for this store's anchored owner
    /// whose sequence is at or below the adopted high-water mark.
    ///
    /// Only a verified owner checkpoint bound to this store may trigger the
    /// stale-delta drop: an unverifiable or cross-store checkpoint falls
    /// through to the sender-auth path unchanged, so a forged checkpoint
    /// cannot be used to suppress legitimate writes. The writer's wire
    /// signature covers the whole delta (checkpoint included), so a relay
    /// cannot graft a stale checkpoint onto a fresh owner delta either.
    fn is_subsumed_by_adopted_checkpoint(&self, cp: &OwnerCheckpoint) -> bool {
        if cp.checkpoint_seq > self.highest_checkpoint_seq {
            return false;
        }
        let Some(expected_owner) = self.owner else {
            return false;
        };
        if cp.verify(&expected_owner).is_err() {
            return false;
        }
        cp.store_id == self.id
    }

    /// After applying an incremental mutation via the sender-auth path, cache
    /// the checkpoint if the resulting complete state matches the checkpoint's
    /// content root.
    ///
    /// This ensures a relay always carries the latest checkpoint after normal
    /// multi-write/update/delete operations: after the owner publishes an
    /// incremental delta (single-entry), the relay applies it, then
    /// recomputes the root over its *complete* state. If it matches the
    /// checkpoint root, the relay caches the checkpoint — so a subsequent
    /// `full_delta` relays the correct, up-to-date checkpoint.
    ///
    /// Does not mutate entries (already applied by the caller); only updates
    /// `latest_checkpoint` and `highest_checkpoint_seq`.
    fn maybe_cache_checkpoint(&mut self, cp: &OwnerCheckpoint) {
        // Only advance for strictly newer checkpoints.
        if cp.checkpoint_seq <= self.highest_checkpoint_seq {
            return;
        }
        // Verify owner binding + signature (the checkpoint must be genuine).
        let Some(expected_owner) = self.owner else {
            return;
        };
        if cp.verify(&expected_owner).is_err() {
            return;
        }
        if cp.store_id != self.id {
            return;
        }
        // Adoption rejects a checkpoint that would downgrade a terminal
        // policy, but an owner-authenticated delta then falls through to the
        // entry merge path. Preserve that entry behavior while refusing to
        // cache the rejected checkpoint or advance its high-water sequence.
        let preserves_terminal_policy = match (&self.policy, &cp.policy) {
            (AccessPolicy::AppendOnly, AccessPolicy::AppendOnly) => true,
            (AccessPolicy::AppendOnly, _) => false,
            (
                AccessPolicy::Encrypted { group_id: current },
                AccessPolicy::Encrypted { group_id: claimed },
            )
            | (
                AccessPolicy::TreeKemEncrypted { group_id: current },
                AccessPolicy::TreeKemEncrypted { group_id: claimed },
            ) => current == claimed,
            (AccessPolicy::Encrypted { .. } | AccessPolicy::TreeKemEncrypted { .. }, _) => false,
            _ => true,
        };
        if !preserves_terminal_policy {
            return;
        }
        // Cache only if the resulting complete state matches the checkpoint.
        if self.local_root_matches(cp) {
            self.latest_checkpoint = Some(cp.clone());
            self.highest_checkpoint_seq = cp.checkpoint_seq;
        }
    }

    /// Merge another store into this one.
    ///
    /// # Errors
    ///
    /// - [`KvError::StoreIdMismatch`] if the ids differ.
    /// - [`KvError::ImmutableKey`] under [`AccessPolicy::AppendOnly`] if the
    ///   merge would remove any locally-active key or change any of its
    ///   frozen fields. The merge is applied transactionally: on violation
    ///   NOTHING is applied (no partial merge). This closes the bypass where
    ///   a full-state merge (which skips every `merge_delta` gate) could
    ///   rewrite or tombstone append-only history. Currently this method has
    ///   no non-test callers — the live sync path is
    ///   [`merge_delta`](Self::merge_delta) — but it is public API, so the
    ///   invariant is enforced here too rather than removed (removal would be
    ///   a semver break; flagged for v0.33.0).
    pub fn merge(&mut self, other: &KvStore) -> Result<()> {
        if self.id != other.id {
            return Err(KvError::StoreIdMismatch);
        }
        if self.is_group_signed()
            || other.is_group_signed()
            || self.is_encrypted()
            || other.is_encrypted()
        {
            return Err(KvError::Merge(
                "group stores require an authenticated retained-image merge".to_string(),
            ));
        }

        // AppendOnly: run the merge on a trial clone and verify the freeze
        // invariant before committing, so a violating merge cannot leave
        // partial state behind.
        if matches!(self.policy, AccessPolicy::AppendOnly) {
            let mut trial = self.clone();
            trial.merge_unchecked(other)?;
            for key in self.keys.elements() {
                let Some(local) = self.get(key) else { continue };
                match trial.get(key) {
                    None => {
                        return Err(KvError::ImmutableKey(key.clone()));
                    }
                    Some(merged) if !entry_frozen_fields_equal(merged, local) => {
                        return Err(KvError::ImmutableKey(key.clone()));
                    }
                    _ => {}
                }
            }
            *self = trial;
            return Ok(());
        }

        self.merge_unchecked(other)
    }

    /// The raw CRDT merge, without the AppendOnly freeze check.
    fn merge_unchecked(&mut self, other: &KvStore) -> Result<()> {
        // #1094 P2 (review of #1963): every entry must sit under its own key
        // and match its hash, checked before anything changes.
        for (key, entry) in &other.entries {
            validate_entry_integrity(key, entry)?;
        }
        self.keys
            .merge_state(&other.keys)
            .map_err(|e| KvError::Merge(format!("OR-Set merge failed: {e}")))?;

        for (key, other_entry) in &other.entries {
            if let Some(our_entry) = self.entries.get_mut(key) {
                our_entry.merge(other_entry);
            } else {
                self.entries.insert(key.clone(), other_entry.clone());
            }
        }

        // Merge allowlists (union)
        for writer in &other.allowed_writers {
            self.allowed_writers.insert(*writer);
        }

        self.name.merge(&other.name);
        self.version += 1;
        Ok(())
    }

    /// Merge a fully retained group CRDT image after its current endorser has
    /// been authenticated by the sync layer.
    ///
    /// #1970: a merge that would grow the canonical retained image past
    /// the retained-image limit is refused typed before anything applies
    /// (and without touching the shared sequence allocator); a merge that
    /// does not grow it past the limit commits, so a holder already past
    /// the limit can still recover by merging newer, smaller state.
    ///
    /// # Errors
    ///
    /// [`KvError::Unauthorized`] on a foreign store/group/owner binding;
    /// [`KvError::ValueTooLarge`] or [`KvError::Merge`] on invalid image
    /// content or OR-Set state; [`KvError::StoreFull`] when the merged
    /// image would grow past the retained-image limit; and
    /// [`KvError::Serialization`] if a measure fails.
    pub fn merge_group_retained_image(
        &mut self,
        other: &KvStore,
        endorser: AgentId,
        local_peer: PeerId,
    ) -> Result<()> {
        let same_binding = self.id == other.id
            && self.owner == other.owner
            && self.name.get() == other.name.get()
            && match (&self.policy, &other.policy) {
                (
                    AccessPolicy::GroupSigned { group_id: ours },
                    AccessPolicy::GroupSigned { group_id: theirs },
                )
                | (
                    AccessPolicy::Encrypted { group_id: ours },
                    AccessPolicy::Encrypted { group_id: theirs },
                )
                | (
                    AccessPolicy::TreeKemEncrypted { group_id: ours },
                    AccessPolicy::TreeKemEncrypted { group_id: theirs },
                ) => ours == theirs,
                _ => false,
            };
        if !same_binding {
            return Err(KvError::Unauthorized(
                "retained group image has a foreign store/group/owner binding".to_string(),
            ));
        }
        // Validate the complete incoming image before touching local state.
        for (key, entry) in &other.entries {
            validate_entry_integrity(key, entry)?;
            if entry.value.len() > crate::kv::entry::MAX_INLINE_SIZE {
                return Err(KvError::ValueTooLarge {
                    size: entry.value.len(),
                    max: crate::kv::entry::MAX_INLINE_SIZE,
                });
            }
        }
        let retained_sequence_floor = self
            .keys
            .max_retained_sequence_for_peer(&local_peer)
            .into_iter()
            .chain(other.keys.max_retained_sequence_for_peer(&local_peer))
            .max();
        if retained_sequence_floor.is_some_and(|floor| floor > u64::MAX - 2) {
            return Err(KvError::Merge(
                "retained group image leaves insufficient local sequence allocator capacity"
                    .to_string(),
            ));
        }

        // #1970: merged in place under an undo journal and kept only when
        // the merged canonical image is at most the hard limit. A refused
        // merge leaves nothing applied and the shared sequence allocator
        // untouched.
        let before = self.retained_image_len()?;
        let keys_version = self.keys.version();
        let snapshot = self.snapshot_without_entries();
        let mut journal = EntryJournal::default();
        if let Err(e) = self.keys.merge_state(&other.keys) {
            self.rollback(snapshot, journal)?;
            return Err(KvError::Merge(format!("OR-Set image merge failed: {e}")));
        }
        for (key, entry) in &other.entries {
            self.journal_merge_entry(key, entry, &mut journal);
        }
        self.settle_retained(None, &mut journal);
        // Remote images contribute retained content only. Identity, policy,
        // checkpoint authority, allowlists, and local sequence state remain
        // locally anchored.
        // A replay of the same complete image from the same current writer
        // must not mint a new serialized retained image solely by bumping the
        // store version. Newly retained tags/tombstones, any full entry-field
        // change, and a new authenticated endorser remain versioned changes.
        let changed = self.keys.version() != keys_version
            || !journal.priors.is_empty()
            || self.last_history_endorser.as_ref() != Some(&endorser);
        self.last_history_endorser = Some(endorser);
        if changed {
            self.version = self.version.saturating_add(1);
        }
        self.admit_or_rollback(snapshot, journal, Some(endorser), before, None)?;
        if let Some(floor) = retained_sequence_floor {
            self.restore_seq_counter(floor);
        }
        self.image.clear(&endorser);
        Ok(())
    }

    /// Import retained content from one locally preserved legacy page store.
    ///
    /// The caller authenticates the current group writer and validates the
    /// exact legacy manifest/snapshot binding. This method deliberately moves
    /// only CRDT content: destination identity, group policy, checkpoints,
    /// allowlists, and persistence authority remain local.
    pub fn merge_legacy_signed_history(
        &mut self,
        source: &KvStore,
        expected_source_owner: AgentId,
        endorser: AgentId,
        local_peer: PeerId,
    ) -> Result<()> {
        Self::validate_legacy_signed_source(source, expected_source_owner)?;
        if !matches!(
            self.policy,
            AccessPolicy::GroupSigned { .. }
                | AccessPolicy::Encrypted { .. }
                | AccessPolicy::TreeKemEncrypted { .. }
        ) {
            return Err(KvError::Unauthorized(
                "legacy import requires a group destination".to_string(),
            ));
        }

        let retained_sequence_floor = self
            .keys
            .max_retained_sequence_for_peer(&local_peer)
            .into_iter()
            .chain(source.keys.max_retained_sequence_for_peer(&local_peer))
            .max();
        if retained_sequence_floor.is_some_and(|floor| floor > u64::MAX - 2) {
            return Err(KvError::Merge(
                "legacy history leaves insufficient local sequence allocator capacity".to_string(),
            ));
        }
        let before = self.retained_image_len()?;
        let keys_version = self.keys.version();
        let snapshot = self.snapshot_without_entries();
        let mut journal = EntryJournal::default();
        if let Err(e) = self.keys.merge_state(&source.keys) {
            self.rollback(snapshot, journal)?;
            return Err(KvError::Merge(format!(
                "legacy OR-Set image merge failed: {e}"
            )));
        }
        for (key, entry) in &source.entries {
            self.journal_merge_entry(key, entry, &mut journal);
        }
        self.settle_retained(None, &mut journal);
        // `merge_state` records a new OR-Set version only when it retains a
        // previously unseen add or tombstone; the journal holds every entry
        // whose logical fields changed.
        let changed = self.keys.version() != keys_version
            || !journal.priors.is_empty()
            || self.last_history_endorser.as_ref() != Some(&endorser);
        self.last_history_endorser = Some(endorser);
        if changed {
            self.version = self.version.saturating_add(1);
        }
        // #1970: legacy history merges into the retained image too.
        self.admit_or_rollback(snapshot, journal, Some(endorser), before, None)?;
        if let Some(floor) = retained_sequence_floor {
            self.restore_seq_counter(floor);
        }
        Ok(())
    }

    /// Validate every retained entry and the exact owner/policy binding
    /// before opening or creating an import destination.
    pub fn validate_legacy_signed_source(
        source: &KvStore,
        expected_source_owner: AgentId,
    ) -> Result<()> {
        if source.policy != AccessPolicy::Signed || source.owner != Some(expected_source_owner) {
            return Err(KvError::Unauthorized(
                "legacy import requires an owner-bound Signed source".to_string(),
            ));
        }
        for (key, entry) in &source.entries {
            validate_entry_integrity(key, entry)?;
            if entry.value.len() > crate::kv::entry::MAX_INLINE_SIZE {
                return Err(KvError::ValueTooLarge {
                    size: entry.value.len(),
                    max: crate::kv::entry::MAX_INLINE_SIZE,
                });
            }
        }
        Ok(())
    }

    /// Active keys for which source and destination currently carry
    /// different retained values. The CRDT merge still decides the winner;
    /// this list makes that decision visible to the explicit importer.
    #[must_use]
    pub fn legacy_import_conflicts(&self, source: &KvStore) -> Vec<String> {
        let mut conflicts = source
            .active_keys()
            .into_iter()
            .filter(|key| {
                self.get(key)
                    .zip(source.get(key))
                    .is_some_and(|(ours, theirs)| {
                        ours.value != theirs.value || ours.content_type != theirs.content_type
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        conflicts.sort();
        conflicts
    }

    /// Current writer who authenticated the most recently imported retained
    /// history image. This does not claim authorship of historical entries.
    #[must_use]
    pub fn last_history_endorser(&self) -> Option<&AgentId> {
        self.last_history_endorser.as_ref()
    }

    /// Test seam: set the persisted endorser directly (snapshot-format tests).
    #[cfg(test)]
    pub(crate) fn set_last_history_endorser_for_test(&mut self, endorser: Option<AgentId>) {
        self.last_history_endorser = endorser;
    }

    /// Generate a delta containing all state (for initial sync).
    pub fn full_delta(&self) -> Result<KvStoreDelta> {
        let mut delta = KvStoreDelta::new(self.version);
        let active = self.keys.elements();
        let first_sequence = if active.is_empty() {
            None
        } else {
            Some(
                self.reserve_sequences(u64::try_from(active.len()).map_err(|_| {
                    KvError::Merge(
                        "active key count exceeds sequence allocator capacity".to_string(),
                    )
                })?)?,
            )
        };

        // Walk the active-key OR-Set directly and look entries up, rather than
        // cloning the whole key set into an intermediate HashSet first.
        for (offset, key) in active.into_iter().enumerate() {
            if let Some(entry) = self.entries.get(key) {
                // Synthetic tags must be FRESH per entry (F3, fix-loop):
                // the digest-verified adopt prunes stale keys with a local
                // observe-remove, which tombstones the tags a previous full
                // delta used. A hardcoded tag would then be silently
                // rejected on a later serve that re-adds the key — a
                // permanent re-add deadlock. Minting from the store's own
                // counter guarantees a re-serve's tag is never one this
                // store has issued before (snapshot persistence floors the
                // counter across restarts, so that holds after a restart
                // too). The zero peer id is fine: tags are scoped per key,
                // and uniqueness over time is what the tombstones require.
                let offset = u64::try_from(offset).map_err(|_| {
                    KvError::Merge("active key offset exceeds sequence allocator capacity".into())
                })?;
                let sequence = first_sequence
                    .and_then(|first| first.checked_add(offset))
                    .ok_or_else(|| KvError::Merge("sequence allocator exhausted".into()))?;
                let tag = (PeerId::new([0u8; 32]), sequence);
                delta.added.insert(key.clone(), (entry.clone(), tag));
            }
        }

        delta.name_update = Some(self.name.clone());

        // Include allowlist in full delta
        if !self.allowed_writers.is_empty() {
            delta.allowlist_additions = Some(self.allowed_writers.iter().copied().collect());
        }
        // Relay the latest owner-signed checkpoint so an anchored joiner can
        // cold-recover this store's content even when relayed by a non-owner
        // (the checkpoint's owner signature survives re-wrap).
        delta.owner_checkpoint = self.latest_checkpoint.clone();
        Ok(delta)
    }

    /// The content digest this store declares in a `StateServedV2` marker
    /// when it serves its full state (issue #240). Computed over the active
    /// entry set — see [`served_content_digest`].
    pub(crate) fn served_digest(&self) -> [u8; 32] {
        served_content_digest(&self.id, &self.checkpoint_pairs())
    }

    /// BLAKE3 over a domain tag, the store id and the canonical retained
    /// OR-Set: live tags and tombstones in canonical order, with the
    /// replica-local version and changelog cleared. Two replicas with the
    /// same OR-Set state give the same digest whatever their values (#2110).
    ///
    /// Cached until the store version or the OR-Set version moves.
    pub(crate) fn orset_digest(&self) -> Result<[u8; 32]> {
        let at = (self.version, self.keys.version());
        let mut cache = self
            .orset_digest_cache
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((version, keys_version, digest)) = *cache {
            if (version, keys_version) == at {
                return Ok(digest);
            }
        }
        let digest = self.orset_digest_uncached()?;
        *cache = Some((at.0, at.1, digest));
        Ok(digest)
    }

    #[cfg(test)]
    pub(crate) fn keys_canonical_for_test(
        &self,
    ) -> saorsa_gossip_crdt_sync::CanonicalRetainedOrSet<String> {
        self.keys.canonical_retained_wire()
    }

    #[cfg(test)]
    pub(crate) fn set_id_for_test(&mut self, id: KvStoreId) {
        self.id = id;
    }

    pub(crate) fn orset_digest_uncached(&self) -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"x0x.kv.orset-digest.v1");
        hasher.update(self.id.as_bytes());
        bincode::serialize_into(&mut hasher, &self.keys.canonical_retained_wire())?;
        Ok(*hasher.finalize().as_bytes())
    }

    /// #2110: whether a matching OR-Set digest from `source` may wake a
    /// repair inside its retry window; true at most once per window.
    pub(crate) fn take_image_orset_skip(&mut self, source: &AgentId) -> bool {
        self.image.take_orset_skip(source, now_ms())
    }

    /// Test-only: record a refused image merge from `source`, so its
    /// pulls wait for the retry window.
    #[cfg(test)]
    pub(crate) fn refuse_image_source_for_test(&mut self, source: AgentId) {
        self.image.note_refusal(source, 0, now_ms());
    }

    #[cfg(test)]
    pub(crate) fn clear_image_source_for_test(&mut self, source: &AgentId) {
        self.image.clear(source);
    }

    /// Remove local keys absent from a digest-verified full-state serve
    /// (`delta.added` is then the verified complete entry set).
    ///
    /// This is the checkpoint-less deletion cold-sync path (issue #240): a
    /// plain full-delta merge only upserts, so keys the holder deleted while
    /// this replica was away would otherwise linger forever. Each stale key
    /// is removed with a LOCAL observe-remove (its current tags are
    /// tombstoned, so a later re-add with fresh tags still wins) and dropped
    /// from `entries` — the same semantics the `delta.removed` merge path
    /// applies. Never for AppendOnly stores: keys are immutable there
    /// (mirrors the `removed` guard in `merge_delta`).
    ///
    /// Callers MUST have verified the delta against the serving holder's
    /// declared digest (and its sender authorization) first — without that
    /// binding, any holder could truncate local state at will.
    pub(crate) fn prune_to_served_set(&mut self, delta: &KvStoreDelta) -> usize {
        if matches!(
            self.policy,
            AccessPolicy::AppendOnly | AccessPolicy::SelfKeyed
        ) {
            // SelfKeyed is prune-free for the same reason Allowlisted is:
            // a peer's serve can legitimately omit co-writers' keys (the
            // listener's sole-author gate already restricts pruning to
            // Signed; this guard keeps any future caller from truncating a
            // directory).
            return 0;
        }
        let stale: Vec<String> = self
            .keys
            .elements()
            .into_iter()
            .filter(|k| !delta.added.contains_key(k.as_str()))
            .cloned()
            .collect();
        let mut pruned = 0;
        for key in stale {
            let _ = self.keys.remove(&key);
            self.entries.remove(key.as_str());
            pruned += 1;
        }
        pruned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    pub(super) fn peer(n: u8) -> PeerId {
        PeerId::new([n; 32])
    }

    pub(super) fn store_id(n: u8) -> KvStoreId {
        KvStoreId::new([n; 32])
    }

    #[test]
    fn test_new_store() {
        let owner = agent(1);
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed)
            .expect("kv store");
        assert_eq!(store.name(), "Test");
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
        assert_eq!(store.owner(), Some(&owner));
        assert_eq!(*store.policy(), AccessPolicy::Signed);
    }

    #[test]
    fn test_put_and_get() {
        let p = peer(1);
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        )
        .expect("kv store");

        store
            .put(
                "key1".to_string(),
                b"hello".to_vec(),
                "text/plain".to_string(),
                p,
            )
            .expect("put");

        let entry = store.get("key1").expect("get");
        assert_eq!(entry.value, b"hello");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_put_update() {
        let p = peer(1);
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        )
        .expect("kv store");

        store
            .put(
                "key1".to_string(),
                b"old".to_vec(),
                "text/plain".to_string(),
                p,
            )
            .expect("put");
        store
            .put(
                "key1".to_string(),
                b"new".to_vec(),
                "text/plain".to_string(),
                p,
            )
            .expect("put");

        assert_eq!(store.get("key1").expect("get").value, b"new");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_remove() {
        let p = peer(1);
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        )
        .expect("kv store");

        store
            .put(
                "key1".to_string(),
                b"val".to_vec(),
                "text/plain".to_string(),
                p,
            )
            .expect("put");
        store.remove("key1").expect("remove");
        assert!(store.get("key1").is_none());
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        )
        .expect("kv store");
        assert!(store.remove("nope").is_err());
    }

    #[test]
    fn test_value_too_large() {
        let p = peer(1);
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        )
        .expect("kv store");
        let big = vec![0u8; 100_000];
        let result = store.put(
            "big".to_string(),
            big,
            "application/octet-stream".to_string(),
            p,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_active_keys() {
        let p = peer(1);
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        )
        .expect("kv store");

        store
            .put("a".to_string(), b"1".to_vec(), "text/plain".to_string(), p)
            .expect("put");
        store
            .put("b".to_string(), b"2".to_vec(), "text/plain".to_string(), p)
            .expect("put");
        store
            .put("c".to_string(), b"3".to_vec(), "text/plain".to_string(), p)
            .expect("put");

        assert_eq!(store.active_keys().len(), 3);
    }

    #[test]
    fn test_merge_stores() {
        let p1 = peer(1);
        let p2 = peer(2);
        let id = store_id(1);
        let owner = agent(1);

        let mut s1 =
            KvStore::new(id, "Store".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        let mut s2 =
            KvStore::new(id, "Store".to_string(), owner, AccessPolicy::Signed).expect("kv store");

        s1.put("a".to_string(), b"1".to_vec(), "text/plain".to_string(), p1)
            .expect("put");
        s2.put("b".to_string(), b"2".to_vec(), "text/plain".to_string(), p2)
            .expect("put");

        s1.merge(&s2).expect("merge");
        assert_eq!(s1.len(), 2);
    }

    #[test]
    fn test_merge_different_ids_fails() {
        let owner = agent(1);
        let mut s1 = KvStore::new(store_id(1), "A".to_string(), owner, AccessPolicy::Signed)
            .expect("kv store");
        let s2 = KvStore::new(store_id(2), "B".to_string(), owner, AccessPolicy::Signed)
            .expect("kv store");
        assert!(s1.merge(&s2).is_err());
    }

    #[test]
    fn test_version_increments() {
        let p = peer(1);
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        )
        .expect("kv store");
        assert_eq!(store.current_version(), 0);

        store
            .put("k".to_string(), b"v".to_vec(), "text/plain".to_string(), p)
            .expect("put");
        assert_eq!(store.current_version(), 1);

        store.remove("k").expect("remove");
        assert_eq!(store.current_version(), 2);
    }

    #[test]
    fn test_store_id_from_content() {
        let a = agent(1);
        let id1 = KvStoreId::from_content("store1", &a);
        let id2 = KvStoreId::from_content("store1", &a);
        let id3 = KvStoreId::from_content("store2", &a);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let p = peer(1);
        let mut store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        )
        .expect("kv store");
        store
            .put(
                "key1".to_string(),
                b"val".to_vec(),
                "text/plain".to_string(),
                p,
            )
            .expect("put");

        let bytes = bincode::serialize(&store).expect("serialize");
        let restored: KvStore = bincode::deserialize(&bytes).expect("deserialize");

        assert_eq!(store.id(), restored.id());
        assert_eq!(store.name(), restored.name());
        assert_eq!(store.len(), restored.len());
    }

    #[test]
    fn pre_wave_kvstore_blob_decodes_with_trailing_fields_defaulted() {
        // Regression guard for the mid-struct bincode footgun. The ownership
        // (anchor_channel, policy_version, ownership_conflict) and checkpoint
        // (latest_checkpoint, highest_checkpoint_seq) fields were added by the
        // security wave. bincode is positional, so those fields MUST be trailing
        // AND decoded with `de_tolerant`; otherwise a blob written by the
        // original `KvStore` shape (id..version) fails with UnexpectedEof.
        //
        // This mirror is the EXACT original serialized shape at commit b573441:
        // id, keys, entries, name, policy, owner, allowed_writers, version.
        #[derive(Serialize)]
        struct PreWaveKvStore<'a> {
            id: &'a KvStoreId,
            keys: &'a OrSet<String>,
            entries: &'a HashMap<String, KvEntry>,
            name: &'a LwwRegister<String>,
            policy: &'a AccessPolicy,
            owner: &'a Option<AgentId>,
            allowed_writers: &'a HashSet<AgentId>,
            version: u64,
        }

        let owner = agent(1);
        let mut store = KvStore::new(
            store_id(1),
            "Legacy".to_string(),
            owner,
            AccessPolicy::Signed,
        )
        .expect("kv store");
        store
            .put(
                "k".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");

        let legacy = PreWaveKvStore {
            id: &store.id,
            keys: &store.keys,
            entries: &store.entries,
            name: &store.name,
            policy: &store.policy,
            owner: &store.owner,
            allowed_writers: &store.allowed_writers,
            version: store.version,
        };
        let bytes = bincode::serialize(&legacy).expect("serialize pre-wave shape");
        let restored: KvStore =
            bincode::deserialize(&bytes).expect("pre-wave blob (id..version) must decode");

        // Original content survives.
        assert_eq!(restored.id(), store.id(), "id preserved");
        assert_eq!(restored.len(), 1, "entries preserved");
        assert_eq!(restored.owner, store.owner, "owner preserved");
        // All five wave-added trailing fields default cleanly.
        assert!(
            restored.latest_checkpoint.is_none(),
            "latest_checkpoint defaults"
        );
        assert_eq!(restored.highest_checkpoint_seq, 0, "high-water defaults");
        assert_eq!(
            restored.anchor_channel,
            AnchorChannel::default(),
            "anchor_channel defaults"
        );
        assert_eq!(restored.policy_version, 0, "policy_version defaults");
        assert!(
            restored.ownership_conflict.is_none(),
            "ownership_conflict defaults"
        );
    }

    #[test]
    fn test_next_seq_monotonic() {
        let store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Signed,
        )
        .expect("kv store");
        let s1 = store.next_seq().expect("sequence");
        let s2 = store.next_seq().expect("sequence");
        assert!(s2 > s1);
    }

    // -- Access control tests --

    #[test]
    fn test_signed_policy_owner_authorized() {
        let owner = agent(1);
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed)
            .expect("kv store");
        assert!(store.is_authorized(&owner));
    }

    #[test]
    fn test_signed_policy_non_owner_rejected() {
        let owner = agent(1);
        let other = agent(2);
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed)
            .expect("kv store");
        assert!(!store.is_authorized(&other));
    }

    #[test]
    fn test_signed_policy_rejects_unauthorized_delta() {
        let owner = agent(1);
        let attacker = agent(99);
        let mut store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed)
            .expect("kv store");

        let entry = KvEntry::new(
            "spam".to_string(),
            b"junk".to_vec(),
            "text/plain".to_string(),
        );
        let delta = KvStoreDelta::for_put("spam".to_string(), entry, (peer(99), 1), 1);

        // Merge should succeed (silent rejection) but not apply the delta
        store
            .merge_delta(&delta, peer(99), Some(&attacker))
            .expect("should not error");
        assert!(store.get("spam").is_none(), "spam should be rejected");
    }

    #[test]
    fn test_signed_policy_accepts_owner_delta() {
        let owner = agent(1);
        let mut store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed)
            .expect("kv store");

        let entry = KvEntry::new(
            "legit".to_string(),
            b"data".to_vec(),
            "text/plain".to_string(),
        );
        let delta = KvStoreDelta::for_put("legit".to_string(), entry, (peer(1), 1), 1);

        store
            .merge_delta(&delta, peer(1), Some(&owner))
            .expect("merge");
        assert!(store.get("legit").is_some());
    }

    #[test]
    fn test_allowlisted_policy() {
        let owner = agent(1);
        let writer = agent(2);
        let outsider = agent(3);

        let mut store = KvStore::new(
            store_id(1),
            "Team".to_string(),
            owner,
            AccessPolicy::Allowlisted,
        )
        .expect("kv store");

        // Owner can add writers
        store.allow_writer(writer, &owner).expect("allow");

        assert!(store.is_authorized(&owner));
        assert!(store.is_authorized(&writer));
        assert!(!store.is_authorized(&outsider));
    }

    #[test]
    fn test_allowlisted_rejects_non_owner_allowlist_change() {
        let owner = agent(1);
        let other = agent(2);

        let mut store = KvStore::new(
            store_id(1),
            "Team".to_string(),
            owner,
            AccessPolicy::Allowlisted,
        )
        .expect("kv store");

        let result = store.allow_writer(agent(3), &other);
        assert!(result.is_err());
    }

    #[test]
    fn test_deny_writer() {
        let owner = agent(1);
        let writer = agent(2);

        let mut store = KvStore::new(
            store_id(1),
            "Team".to_string(),
            owner,
            AccessPolicy::Allowlisted,
        )
        .expect("kv store");

        store.allow_writer(writer, &owner).expect("allow");
        assert!(store.is_authorized(&writer));

        store.deny_writer(&writer, &owner).expect("deny");
        assert!(!store.is_authorized(&writer));
    }

    #[test]
    fn test_allowlist_delta_propagation() {
        let owner = agent(1);
        let writer = agent(2);

        let mut store = KvStore::new(
            store_id(1),
            "Team".to_string(),
            owner,
            AccessPolicy::Allowlisted,
        )
        .expect("kv store");
        store.allow_writer(writer, &owner).expect("allow");

        // Full delta should include the allowlist
        let delta = store.full_delta().expect("full delta");
        assert!(delta.allowlist_additions.is_some());
        assert!(delta
            .allowlist_additions
            .as_ref()
            .is_some_and(|a| a.contains(&writer)));
    }

    #[test]
    fn test_anonymous_delta_rejected_for_signed_store() {
        let owner = agent(1);
        let mut store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed)
            .expect("kv store");

        let entry = KvEntry::new(
            "anon".to_string(),
            b"spam".to_vec(),
            "text/plain".to_string(),
        );
        let delta = KvStoreDelta::for_put("anon".to_string(), entry, (peer(99), 1), 1);

        // No writer identity → rejected silently
        store
            .merge_delta(&delta, peer(99), None)
            .expect("silent rejection");
        assert!(store.get("anon").is_none());
    }

    // -- Local write authorization (fail closed) --
    //
    // WHY: a non-owner joiner that mutates its local replica creates a fork
    // the owner's replica rejects — the local path must enforce the same
    // policy as the inbound path.

    #[test]
    fn test_local_write_owner_authorized_on_signed_store() {
        let owner = agent(1);
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed)
            .expect("kv store");
        store
            .authorize_local_write(&owner)
            .expect("owner must be able to write locally");
    }

    #[test]
    fn test_local_write_non_owner_rejected_on_signed_store() {
        let owner = agent(1);
        let joiner = agent(2);
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed)
            .expect("kv store");
        let err = store
            .authorize_local_write(&joiner)
            .expect_err("non-owner local write must be rejected, not silently applied");
        assert!(matches!(err, KvError::Unauthorized(_)));
        assert!(
            format!("{err}").contains(&hex::encode(owner.as_bytes())),
            "rejection must name the true owner so the caller can tell why"
        );
    }

    #[test]
    fn test_no_anchor_join_is_read_only_unknown() {
        // A joined replica with no expected owner is permanently read-only by
        // design — the protocol never derives ownership from the network.
        let joiner = agent(2);
        let store =
            KvStore::new_replica(store_id(1), String::new(), None, AnchorChannel::Persistence);
        assert!(
            store.owner().is_none(),
            "no-anchor replica must not claim an owner"
        );
        assert!(matches!(store.ownership_source(), OwnershipSource::Unknown));
        let err = store
            .authorize_local_write(&joiner)
            .expect_err("write on no-anchor store must fail closed");
        assert!(matches!(err, KvError::OwnerUnknown));
    }

    #[test]
    fn test_no_anchor_replica_rejects_inbound_deltas() {
        // Fail closed on the inbound side too: without an anchored owner there
        // is no authorized writer, so nothing merges (no silent mutation).
        let mut store =
            KvStore::new_replica(store_id(1), String::new(), None, AnchorChannel::Persistence);
        let entry = KvEntry::new("k".to_string(), b"v".to_vec(), "text/plain".to_string());
        let delta = KvStoreDelta::for_put("k".to_string(), entry, (peer(9), 1), 1);
        store
            .merge_delta(&delta, peer(9), Some(&agent(9)))
            .expect("silent rejection");
        assert!(store.get("k").is_none());
    }

    // -- learn_ownership: ownership is construction-only; announce can only
    //    refresh policy or record a conflict. It can NEVER establish ownership. --

    #[test]
    fn test_learn_ownership_rejects_third_party_assignment() {
        // A third party must not assign ownership: the verified sender must
        // equal the claimed owner.
        let mut store =
            KvStore::new_replica(store_id(1), String::new(), None, AnchorChannel::Persistence);
        let owner = agent(1);
        let rogue = agent(9);
        let err = store
            .learn_ownership(owner, AccessPolicy::Signed, 0, &rogue)
            .expect_err("third-party ownership claim must be rejected");
        assert!(matches!(err, KvError::OwnerTokenInvalid(_)));
        assert!(store.owner().is_none());
    }

    #[test]
    fn test_learn_ownership_rejects_none_to_some_first_capture_guard() {
        // THE REGRESSION GUARD: even a verified SELF-claim must NOT establish
        // ownership on a store that has none. `verified_sender == owner` is
        // trivially satisfied by any self-claim, so allowing None→Some would
        // let any agent that speaks first seize the topic (first-self-capture).
        let mut store =
            KvStore::new_replica(store_id(1), String::new(), None, AnchorChannel::Persistence);
        let rogue = agent(9);
        let err = store
            .learn_ownership(rogue, AccessPolicy::Signed, 0, &rogue)
            .expect_err("self-claim must not establish ownership on a no-anchor store");
        assert!(matches!(err, KvError::OwnerTokenInvalid(_)));
        assert!(
            store.owner().is_none(),
            "ownership must remain unestablished"
        );
        assert!(matches!(store.ownership_source(), OwnershipSource::Unknown));
    }

    #[test]
    fn test_anchored_join_merges_owner_deltas_rejects_rogue() {
        // Legitimate expected owner: anchored at construction. The owner's
        // deltas merge; a rogue's are rejected. This also covers the
        // v0.30.1-owner path — no announce is consulted on the data path.
        let owner = agent(1);
        let joiner = agent(2);
        let rogue = agent(9);
        let mut store = KvStore::new_replica(
            store_id(1),
            String::new(),
            Some(owner),
            AnchorChannel::RestParam,
        );
        assert_eq!(store.owner(), Some(&owner));
        assert!(matches!(
            store.ownership_source(),
            OwnershipSource::Anchored {
                owner: _,
                channel: AnchorChannel::RestParam
            }
        ));

        // Local write by the joiner (not the owner): rejected.
        assert!(matches!(
            store.authorize_local_write(&joiner),
            Err(KvError::Unauthorized(_))
        ));

        // Inbound owner delta: accepted.
        let entry = KvEntry::new("ok".to_string(), b"v".to_vec(), "text/plain".to_string());
        let delta = KvStoreDelta::for_put("ok".to_string(), entry, (peer(1), 1), 1);
        store
            .merge_delta(&delta, peer(1), Some(&owner))
            .expect("owner delta merges");
        assert!(store.get("ok").is_some());

        // Inbound rogue delta: rejected.
        let entry = KvEntry::new("bad".to_string(), b"x".to_vec(), "text/plain".to_string());
        let delta = KvStoreDelta::for_put("bad".to_string(), entry, (peer(9), 1), 2);
        store
            .merge_delta(&delta, peer(9), Some(&rogue))
            .expect("silent rejection");
        assert!(store.get("bad").is_none());
    }

    #[test]
    fn test_first_capture_impossible_against_anchored_joiner() {
        // An anchored joiner ignores a rogue's self-announce that arrives
        // first; the legitimate owner's later announce refreshes policy only.
        let owner = agent(1);
        let rogue = agent(9);
        let mut store = KvStore::new_replica(
            store_id(1),
            String::new(),
            Some(owner),
            AnchorChannel::RestParam,
        );

        // Rogue speaks first, attesting to itself.
        let err = store
            .learn_ownership(rogue, AccessPolicy::Allowlisted, 5, &rogue)
            .expect_err("rogue self-claim against anchored owner must conflict");
        assert!(
            matches!(err, KvError::OwnershipConflict { anchored, claimed } if anchored == owner && claimed == rogue)
        );
        assert_eq!(store.owner(), Some(&owner), "anchored owner unchanged");
        assert!(matches!(
            store.ownership_source(),
            OwnershipSource::Conflict { anchored, announced }
                if anchored == owner && announced == rogue
        ));

        // Legitimate owner announces with a forward policy_version: refresh is
        // applied and the recorded conflict is cleared.
        store
            .learn_ownership(owner, AccessPolicy::Allowlisted, 1, &owner)
            .expect("owner policy refresh");
        assert_eq!(*store.policy(), AccessPolicy::Allowlisted);
        assert!(matches!(
            store.ownership_source(),
            OwnershipSource::Anchored {
                owner: _,
                channel: AnchorChannel::RestParam
            }
        ));
    }

    #[test]
    fn test_ownership_immutable_conflict() {
        // Once anchored, ownership is immutable; a conflicting claim is
        // rejected and the conflict surfaced (ownership_status: conflict).
        let owner = agent(1);
        let hijacker = agent(9);
        let mut store = KvStore::new_replica(
            store_id(1),
            String::new(),
            Some(owner),
            AnchorChannel::RestParam,
        );
        let err = store
            .learn_ownership(hijacker, AccessPolicy::Signed, 0, &hijacker)
            .expect_err("conflicting ownership claim must be rejected");
        assert!(
            matches!(err, KvError::OwnershipConflict { anchored, claimed } if anchored == owner && claimed == hijacker)
        );
        assert_eq!(store.owner(), Some(&owner));
        assert!(matches!(
            store.ownership_source(),
            OwnershipSource::Conflict { anchored, announced }
                if anchored == owner && announced == hijacker
        ));
    }

    #[test]
    fn test_policy_refresh_monotonic_blocks_replay_downgrade() {
        // A forward policy_version refresh applies; a replayed older one is
        // dropped (no downgrade).
        let owner = agent(1);
        let mut store = KvStore::new_replica(
            store_id(1),
            String::new(),
            Some(owner),
            AnchorChannel::RestParam,
        );
        // Owner refreshes to Allowlisted at version 2.
        store
            .learn_ownership(owner, AccessPolicy::Allowlisted, 2, &owner)
            .expect("forward refresh applies");
        assert_eq!(*store.policy(), AccessPolicy::Allowlisted);
        assert_eq!(store.policy_version(), 2);

        // Replayed older announce (version 1, Signed) must NOT downgrade.
        store
            .learn_ownership(owner, AccessPolicy::Signed, 1, &owner)
            .expect("stale replay dropped without error");
        assert_eq!(
            *store.policy(),
            AccessPolicy::Allowlisted,
            "policy not downgraded"
        );
        assert_eq!(store.policy_version(), 2);
    }

    #[test]
    fn test_store_id_for_topic_owner_binds_owner() {
        // for_topic_owner is the verifiable topic→owner binding: creator and
        // anchored joiner agree, and a different owner yields a different id.
        let owner = agent(1);
        let rogue = agent(9);
        let creator_id = KvStoreId::for_topic_owner("store/x", &owner);
        let joiner_id = KvStoreId::for_topic_owner("store/x", &owner);
        assert_eq!(creator_id, joiner_id, "creator and joiner agree on id");
        assert_ne!(
            KvStoreId::for_topic_owner("store/x", &owner),
            KvStoreId::for_topic_owner("store/x", &rogue),
            "different owner => different id"
        );
        // Distinct from the legacy from_content domain.
        assert_ne!(
            KvStoreId::for_topic_owner("store/x", &owner),
            KvStoreId::from_content("store/x", &owner)
        );
    }

    #[test]
    fn test_v0_30_1_owner_converges_with_anchored_joiner_no_announce() {
        // A v0.30.1 owner NEVER announces ownership. An anchored v0.31 joiner
        // still converges because the data path (merge_delta) authorizes
        // against the construction-time owner — no announce is consulted.
        let owner = agent(1);
        let joiner_agent = agent(2);
        // Owner-side store with a written key, republished as a full delta
        // (exactly what a holder — including a v0.30.1 owner — sends on a
        // StateRequest).
        let mut owner_store =
            KvStore::new(store_id(1), "S".to_string(), owner, AccessPolicy::Signed)
                .expect("kv store");
        owner_store
            .put(
                "k".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner put");
        let full = owner_store.full_delta().expect("full delta");
        // Anchored joiner — no learn_ownership / announce ever happens.
        let mut joiner = KvStore::new_replica(
            store_id(1),
            String::new(),
            Some(owner),
            AnchorChannel::RestParam,
        );
        joiner
            .merge_delta(&full, peer(1), Some(&owner))
            .expect("owner full-delta merges on an anchored joiner");
        assert!(
            joiner.get("k").is_some(),
            "anchored joiner converges against a v0.30.1 owner with no announce"
        );
        // The joiner is not the owner, so it still cannot write locally.
        assert!(matches!(
            joiner.authorize_local_write(&joiner_agent),
            Err(KvError::Unauthorized(_))
        ));
        // And a no-anchor joiner in the same scenario stays empty (fail
        // closed) — explicit incompatibility, not a silent deadlock.
        let mut unanchored =
            KvStore::new_replica(store_id(1), String::new(), None, AnchorChannel::Persistence);
        unanchored
            .merge_delta(&full, peer(1), Some(&owner))
            .expect("silent rejection");
        assert!(unanchored.get("k").is_none());
    }

    #[test]
    fn encrypted_new_is_reserved() {
        // WHY (#341 Phase A, I0): the Encrypted policy names group-scoped
        // confidentiality, but secure sync is not wired — a constructible
        // replica would gossip plaintext while authorizing every writer.
        // The constructor must refuse it with the DEDICATED reserved error,
        // never OwnerUnknown (this is not an ownership problem) and never
        // a live store.
        let err = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Encrypted {
                group_id: vec![1, 2, 3],
            },
        )
        .expect_err("Encrypted policy must not be constructible");
        assert!(
            matches!(
                &err,
                KvError::EncryptedPolicyReserved { group_id } if group_id == &vec![1, 2, 3]
            ),
            "expected EncryptedPolicyReserved, got {err:?}"
        );
        assert!(
            !matches!(err, KvError::OwnerUnknown),
            "the reserved-policy reject must never surface as OwnerUnknown"
        );

        // Every wired policy still constructs.
        for policy in [
            AccessPolicy::Signed,
            AccessPolicy::Allowlisted,
            AccessPolicy::AppendOnly,
        ] {
            assert!(
                KvStore::new(store_id(1), "Test".to_string(), agent(1), policy.clone()).is_ok(),
                "{policy} must stay constructible"
            );
        }
    }

    #[test]
    fn encrypted_fail_closed_if_forced() {
        // WHY (#341 Phase A, I1): a legacy/deserialized replica CAN carry
        // the reserved Encrypted policy even though no constructor builds
        // one anymore. Such a replica must fail closed: nobody authorized,
        // no local writes, and no delta application — anonymous or signed —
        // until secure sync is wired. `new_encrypted_unchecked` is the
        // test-only bypass that proves these arms.
        let owner = agent(1);
        let anyone = agent(9);
        let id = store_id(1);

        let mut dest =
            KvStore::new_encrypted_unchecked(id, "Test".to_string(), owner, vec![1, 2, 3]);

        // is_authorized: false for everyone, the anchored owner included.
        assert!(!dest.is_authorized(&owner), "owner is not authorized");
        assert!(!dest.is_authorized(&anyone), "stranger is not authorized");

        // authorize_local_write: dedicated reserved error, not Ok, not
        // Unauthorized, not OwnerUnknown.
        for writer in [&owner, &anyone] {
            let err = dest
                .authorize_local_write(writer)
                .expect_err("local writes must fail on a forced Encrypted replica");
            assert!(
                matches!(
                    &err,
                    KvError::EncryptedPolicyReserved { group_id } if group_id == &vec![1, 2, 3]
                ),
                "expected EncryptedPolicyReserved, got {err:?}"
            );
        }

        // merge_delta: a real delta from a source store applies NOTHING —
        // neither anonymously (writer == None) nor with a named writer
        // (even the owner). Silent-for-spam Ok, but nothing lands.
        let mut source =
            KvStore::new(id, "Test".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        source
            .put(
                "k".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("source put");
        let delta = source.full_delta().expect("full delta");
        let v_before = dest.current_version();

        dest.merge_delta(&delta, peer(2), None)
            .expect("anonymous merge is a silent reject, not an error");
        assert!(dest.get("k").is_none(), "anonymous delta applied nothing");

        dest.merge_delta(&delta, peer(2), Some(&owner))
            .expect("signed merge is a silent reject, not an error");
        assert!(
            dest.get("k").is_none(),
            "owner-signed delta applied nothing"
        );
        dest.merge_delta(&delta, peer(2), Some(&anyone))
            .expect("signed merge is a silent reject, not an error");
        assert!(dest.get("k").is_none(), "stranger delta applied nothing");

        assert_eq!(dest.current_version(), v_before, "no state change at all");
        assert!(dest.is_empty(), "forced Encrypted replica stays empty");
    }

    #[test]
    fn encrypted_replica_rejects_owner_checkpoint_adoption() {
        // WHY (#341 Phase A, I1): checkpoint adoption runs in merge_delta
        // BEFORE the sender-auth check, so `try_adopt_full_snapshot` is the
        // one write path the is_authorized fail-closed arm never sees. A
        // forced Encrypted replica (legacy/deserialized state) receiving a
        // delta with a GENUINE owner checkpoint must not adopt: adoption
        // would apply the plaintext entries and refresh the policy in
        // step 10 — silently flipping Encrypted→Signed and re-opening
        // every write path the reservation closed.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/enc-adopt";
        let id = KvStoreId::for_topic_owner(topic, &owner);

        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        owner_store
            .put(
                "k".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let cp = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut delta = owner_store.full_delta().expect("full delta");
        delta.owner_checkpoint = Some(cp);

        let mut dest = KvStore::new_encrypted_unchecked(id, String::new(), owner, vec![1, 2, 3]);
        let v_before = dest.current_version();
        dest.merge_delta(&delta, peer(9), Some(&owner))
            .expect("silent reject, not an error");
        assert!(
            dest.get("k").is_none(),
            "owner checkpoint must not apply its plaintext entries"
        );
        assert!(dest.is_empty(), "forced Encrypted replica stays empty");
        assert!(
            matches!(dest.policy, AccessPolicy::Encrypted { .. }),
            "policy must stay Encrypted, not flip to Signed"
        );
        assert!(
            dest.latest_checkpoint.is_none(),
            "checkpoint must not be cached"
        );
        assert_eq!(
            dest.highest_checkpoint_seq, 0,
            "high-water mark must stay untouched"
        );
        assert_eq!(dest.current_version(), v_before, "no state change at all");
    }

    #[test]
    fn test_policy_display() {
        assert_eq!(format!("{}", AccessPolicy::Signed), "signed");
        assert_eq!(format!("{}", AccessPolicy::Allowlisted), "allowlisted");
        assert_eq!(
            format!(
                "{}",
                AccessPolicy::Encrypted {
                    group_id: vec![1, 2, 3]
                }
            ),
            "encrypted"
        );
    }

    // -- #341 Phase B: encrypted stores with an attached secure context --

    use crate::kv::encrypted::KvSecureContext;

    /// Fixed-member secure context for store-layer tests — the same
    /// derivation path as the GSS backend without a groups dependency.
    struct TestCtx {
        group_id: Vec<u8>,
        members: std::sync::Mutex<HashSet<AgentId>>,
    }

    impl TestCtx {
        fn new(group: u8, members: &[AgentId]) -> Arc<Self> {
            Arc::new(Self {
                group_id: vec![group; 16],
                members: std::sync::Mutex::new(members.iter().copied().collect()),
            })
        }
    }

    impl KvSecureContext for TestCtx {
        fn group_id(&self) -> Vec<u8> {
            self.group_id.clone()
        }
        fn current_epoch(&self) -> u64 {
            3
        }
        fn seal(
            &self,
            _store_id: &KvStoreId,
            plaintext: &[u8],
        ) -> crate::kv::Result<(u64, [u8; 24], Vec<u8>)> {
            use chacha20poly1305::aead::{Aead, KeyInit, Payload};
            use chacha20poly1305::{XChaCha20Poly1305, XNonce};
            let epoch = self.current_epoch();
            let mut nonce = [0u8; 24];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
            let cipher = XChaCha20Poly1305::new(blake3::hash(&self.group_id).as_bytes().into());
            let ct = cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext,
                        aad: b"test",
                    },
                )
                .map_err(|_| KvError::SecureRecord("test seal failed".to_string()))?;
            Ok((epoch, nonce, ct))
        }
        fn open(
            &self,
            _store_id: &KvStoreId,
            epoch: u64,
            nonce: &[u8; 24],
            ciphertext: &[u8],
        ) -> crate::kv::Result<Vec<u8>> {
            use chacha20poly1305::aead::{Aead, KeyInit, Payload};
            use chacha20poly1305::{XChaCha20Poly1305, XNonce};
            if epoch != self.current_epoch() {
                return Err(KvError::SecureRecord(format!("no key for epoch {epoch}")));
            }
            let cipher = XChaCha20Poly1305::new(blake3::hash(&self.group_id).as_bytes().into());
            cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: b"test",
                    },
                )
                .map_err(|_| KvError::SecureRecord("test open failed".to_string()))
        }
        fn is_active_member(&self, agent: &AgentId) -> bool {
            self.members
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(agent)
        }

        fn invalidate(&self) {
            self.members
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
        }
    }

    /// The removal an owner publishes for a key it does not hold
    /// (#2110): it names only the key.
    fn removal_by_key(key: &str) -> KvStoreDelta {
        let mut delta = KvStoreDelta::new(1);
        delta.removed.insert(key.to_string(), HashSet::new());
        delta
    }

    /// #2110 item 3, group store: a holder that receives the removal
    /// tombstones its tags, and a holder that was offline loses the key at
    /// its next retained-image merge with it.
    #[test]
    fn removal_by_key_reaches_an_offline_holder_of_a_group_store() {
        let owner = agent(1);
        let ctx = TestCtx::new(7, &[owner]);
        let mut holder =
            KvStore::new_group_signed(store_id(8), "Wiki".to_string(), owner, vec![7u8; 16], ctx)
                .expect("holder");
        holder
            .put(
                "k".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let mut offline = holder.clone();
        holder
            .merge_delta(&removal_by_key("k"), peer(2), Some(&owner))
            .expect("removal");
        assert!(holder.get("k").is_none(), "a live holder applies it");
        offline
            .merge_group_retained_image(&holder.served_image_for_test(), agent(7), peer(3))
            .expect("retained image");
        assert!(
            offline.get("k").is_none(),
            "the offline holder loses the key through the image tombstones"
        );
    }

    /// #2110 item 3, plain store: cold sync is a full delta, which carries
    /// no tombstones, so a holder that missed the removal keeps the key.
    #[test]
    fn removal_by_key_does_not_reach_an_offline_holder_of_a_plain_store() {
        let owner = agent(1);
        let mut holder = KvStore::new(
            store_id(9),
            "plain".to_string(),
            owner,
            AccessPolicy::Allowlisted,
        )
        .expect("holder");
        holder
            .put(
                "k".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let mut offline = holder.clone();
        holder
            .merge_delta(&removal_by_key("k"), peer(2), Some(&owner))
            .expect("removal");
        assert!(holder.get("k").is_none(), "a live holder applies it");
        offline
            .merge_delta(
                &holder.full_delta().expect("full delta"),
                peer(2),
                Some(&owner),
            )
            .expect("cold sync");
        assert!(
            offline.get("k").is_some(),
            "known limit: a full delta carries no tombstone"
        );
    }

    #[test]
    fn group_signed_retained_image_preserves_removal_and_concurrent_write() {
        let owner = agent(1);
        let writer = agent(2);
        let ctx = TestCtx::new(7, &[owner, writer]);
        let id = store_id(8);
        let group = vec![7u8; 16];
        let mut source =
            KvStore::new_group_signed(id, "Wiki".to_string(), owner, group.clone(), ctx.clone())
                .expect("source");
        source
            .put(
                "removed".to_string(),
                b"old".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("seed");
        let mut target = source.clone();
        source.remove("removed").expect("remove");
        target
            .put(
                "concurrent".to_string(),
                b"local".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("concurrent");

        let endorser = agent(7);
        target
            .merge_group_retained_image(&source, endorser, peer(2))
            .expect("authenticated retained image");

        assert!(target.get("removed").is_none(), "OR-Set tombstone survives");
        assert_eq!(
            target.get("concurrent").expect("concurrent survives").value,
            b"local"
        );
        assert_eq!(target.owner(), Some(&owner));
        assert_eq!(target.last_history_endorser(), Some(&endorser));
        assert!(matches!(
            target.policy(),
            AccessPolicy::GroupSigned { group_id } if group_id == &group
        ));
    }

    /// Two one-writer group stores for the #1970 regression tests: each
    /// writer's own puts keep its replica under the retained-image limit
    /// (direct `put` takes no put-time gate — the shape of a peer on a
    /// version before #1963, or of a writer the handle-level gate has not
    /// bounded), while the union of the two passes the limit.
    fn two_writers_past_the_limit() -> (KvStore, KvStore, u64) {
        let max = crate::kv::retained_paging::MAX_RETAINED_IMAGE_BYTES as u64;
        let owner = agent(1);
        let ctx = TestCtx::new(7, &[owner]);
        let value = vec![b'v'; 60_000];
        let build = |prefix: char, writer_peer: u8| {
            let mut s = KvStore::new_group_signed(
                store_id(8),
                "Wiki".to_string(),
                owner,
                vec![7u8; 16],
                ctx.clone(),
            )
            .expect("store");
            for i in 0..150u32 {
                s.put(
                    format!("{prefix}{i:05}"),
                    value.clone(),
                    "text/plain".to_string(),
                    peer(writer_peer),
                )
                .expect("put");
            }
            s
        };
        let a = build('a', 1);
        let b = build('b', 2);
        let size_a = bincode::serialized_size(&a).expect("size a");
        let size_b = bincode::serialized_size(&b).expect("size b");
        assert!(size_a <= max, "writer A stays under the limit: {size_a}");
        assert!(size_b <= max, "writer B stays under the limit: {size_b}");
        assert!(
            size_a.saturating_add(size_b) > max,
            "the merged state passes the limit: {size_a} + {size_b}"
        );
        (a, b, max)
    }

    /// #1970: a served retained image whose merge would take the local
    /// image past the retained-image limit is refused with a typed
    /// `StoreFull` and the holder stays servable, instead of merging into
    /// an image that cannot be served to any new or lagging member.
    #[test]
    fn a_merged_retained_image_past_the_limit_is_refused() {
        let (mut a, b, max) = two_writers_past_the_limit();

        match a.merge_group_retained_image(&b, agent(7), peer(2)) {
            Err(KvError::StoreFull { image, .. }) => assert!(image > max),
            other => panic!("expected a typed StoreFull refusal, got {other:?}"),
        }
        assert!(
            a.merge_group_retained_image(&b, agent(7), peer(2)).is_err(),
            "the refusal is stable on replay"
        );
        let size = bincode::serialized_size(&a).expect("size after refusal");
        assert!(size <= max, "the refusing holder stays servable: {size}");
        assert_eq!(
            a.entries.len(),
            150,
            "none of the refused image's entries applied"
        );
    }

    /// #1970: the same two-writer union arriving as a group writer's
    /// content delta (the concurrent-writer and older-peer path) is refused
    /// the same way, before any of its entries apply.
    #[test]
    fn a_group_delta_past_the_limit_is_refused() {
        let (mut a, b, max) = two_writers_past_the_limit();

        // A content-only delta — no name, allowlist or checkpoint rider —
        // as a group writer's `for_put` stream emits.
        let mut delta = KvStoreDelta::new(b.version);
        for (i, (key, entry)) in b.entries.iter().enumerate() {
            delta
                .added
                .insert(key.clone(), (entry.clone(), (peer(2), i as u64)));
        }

        match a.merge_delta(&delta, peer(2), Some(&agent(1))) {
            Err(KvError::StoreFull { image, .. }) => assert!(image > max),
            other => panic!("expected a typed StoreFull refusal, got {other:?}"),
        }
        let size = bincode::serialized_size(&a).expect("size after refusal");
        assert!(size <= max, "the refusing holder stays servable: {size}");
        assert_eq!(
            a.entries.len(),
            150,
            "none of the refused delta's entries applied"
        );
    }

    /// One group store filled to within two 60 KB entries of the
    /// retained-image limit — the closest under-cap state a replica can sit
    /// at, where the merge bound decides. The bulk count and the per-entry
    /// cost come from two serialized measurements; the corrective tail adds
    /// whole entries only, never a measure per put (the review of this PR
    /// flagged that shape as quadratic).
    fn store_within_two_entries_of_the_limit(slot: u8, encrypted: Option<bool>) -> (KvStore, u64) {
        let max = crate::kv::retained_paging::MAX_RETAINED_IMAGE_BYTES as u64;
        let owner = agent(1);
        let ctx = TestCtx::new(7, &[owner]);
        let mut s = match encrypted {
            None => KvStore::new_group_signed(
                store_id(slot),
                "Wiki".to_string(),
                owner,
                vec![7u8; 16],
                ctx,
            ),
            Some(treekem) if treekem => KvStore::new_treekem_encrypted(
                store_id(slot),
                "Wiki".to_string(),
                owner,
                vec![7u8; 16],
                ctx,
            ),
            Some(_) => KvStore::new_encrypted(
                store_id(slot),
                "Wiki".to_string(),
                owner,
                vec![7u8; 16],
                ctx,
            ),
        }
        .expect("store");
        let value = vec![b'v'; 60_000];
        for i in 0..260u32 {
            s.put(
                format!("k{i:05}"),
                value.clone(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        }
        let size_260 = bincode::serialized_size(&s).expect("size");
        s.put(
            "k00260".to_string(),
            value.clone(),
            "text/plain".to_string(),
            peer(1),
        )
        .expect("put");
        let per_entry = bincode::serialized_size(&s).expect("size") - size_260;
        assert!(per_entry > 0, "per-entry cost measured: {per_entry}");
        let fits = (max - bincode::serialized_size(&s).expect("size")) / per_entry;
        for i in 261..(261 + fits.saturating_sub(1)) as u32 {
            s.put(
                format!("k{i:05}"),
                value.clone(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        }
        let size = bincode::serialized_size(&s).expect("size");
        assert!(size <= max, "fixture stays under the limit: {size}");
        assert!(
            max - size < 2 * per_entry,
            "fixture sits within two entries of the limit: {}",
            max - size
        );
        (s, max)
    }

    /// Land a store's raw serialized size exactly at `target` (under the
    /// limit): whole 60 KB entries close the bulk of the gap (each under
    /// the inline cap), then one probe-sized put lands the remainder — a
    /// clone measures the fixed overhead of a fresh key's entry, and the
    /// real put carries the value length that closes what is left.
    /// bincode value bytes are linear, so the landing is exact — this is
    /// how a test places a store within a known few bytes of the limit,
    /// closer than whole entries reach.
    fn land_raw_image_at(s: &mut KvStore, target: u64) {
        fn size_of(s: &KvStore) -> u64 {
            bincode::serialized_size(s).expect("size")
        }
        while size_of(s) + 61_000 > target {
            let mut keys: Vec<String> = s.entries.keys().cloned().collect();
            keys.sort();
            s.remove(&keys[0]).expect("make room");
        }
        let mut sequence = 0u32;
        while target.saturating_sub(size_of(s)) > 60_000 {
            s.put(
                format!("zzz-land-{sequence}"),
                vec![b'l'; 60_000],
                "text/plain".to_string(),
                peer(1),
            )
            .expect("bulk landing put");
            sequence += 1;
        }
        let key = format!("zzz-land-{sequence}");
        let mut probe = s.clone();
        let before = size_of(&probe);
        probe
            .put(
                key.clone(),
                vec![b'p'; 1],
                "text/plain".to_string(),
                peer(1),
            )
            .expect("probe put");
        let overhead = size_of(&probe) - before;
        let current = size_of(s);
        assert!(
            target > current + overhead,
            "target must leave room for the landing put: {target} vs {current}+{overhead}"
        );
        // The probe carried one value byte, so its overhead plus (L - 1)
        // further bytes is the real put's cost.
        let value_len = (target - current - overhead + 1) as usize;
        assert!(
            value_len <= crate::kv::entry::MAX_INLINE_SIZE,
            "the landing put fits the inline cap: {value_len}"
        );
        s.put(
            key,
            vec![b'l'; value_len],
            "text/plain".to_string(),
            peer(1),
        )
        .expect("landing put");
        assert_eq!(size_of(s), target, "the landing put lands exactly");
    }

    /// #1970 review round 2: real overwrites travel as put-shaped deltas
    /// (`for_put` — a fresh tag under `added`), never as `updated`
    /// upserts. A replica sitting at the limit must merge one: its only
    /// canonical growth is one OR-Set tag, and the bound measures the
    /// canonical image, which excludes the changelog entry the re-add
    /// appends. (The pre-fix raw measure counted that changelog entry,
    /// so the replica refused real overwrites — and two replicas with
    /// different re-delivery histories disagreed about where the limit
    /// sat, because the measure included that history.)
    #[test]
    fn a_same_size_overwrite_at_the_limit_merges() {
        let (mut s, max) = store_within_two_entries_of_the_limit(9, None);
        land_raw_image_at(&mut s, max - LOCAL_IMAGE_ALLOWANCE - 400);
        let (key, old) = s
            .entries
            .iter()
            .next()
            .map(|(k, v)| (k.clone(), v.clone()))
            .expect("fixture entry");
        let mut replacement = KvEntry::new(
            key.clone(),
            vec![b'w'; old.value.len()],
            "text/plain".to_string(),
        );
        replacement.updated_at = old.updated_at + 10_000;
        let delta = KvStoreDelta::for_put(key, replacement, (peer(2), 5_000_000), s.version);
        s.merge_delta(&delta, peer(2), Some(&agent(1)))
            .expect("a put-shaped same-size overwrite merges at the limit");
        assert_eq!(
            s.get(delta.added.keys().next().expect("delta key"))
                .expect("entry")
                .value
                .first(),
            Some(&b'w'),
            "the newer same-size value won LWW"
        );
        assert!(
            s.retained_image_len().expect("canonical size") <= max,
            "the merged canonical image stays servable"
        );
    }

    /// #1970 review round 2: gossip replays re-deliver records the
    /// receiver has already merged — same entries, same tags — and each
    /// replay appends only OR-Set changelog bookkeeping. The canonical
    /// image does not grow, so a replica at the limit merges every replay
    /// it is served, however often gossip re-delivers. (The pre-fix raw
    /// measure grew per replay until the store refused records it had
    /// already merged.)
    #[test]
    fn a_redelivered_entry_at_the_limit_merges() {
        let (mut s, max) = store_within_two_entries_of_the_limit(10, None);
        land_raw_image_at(&mut s, max - LOCAL_IMAGE_ALLOWANCE - 400);
        let mut delta = KvStoreDelta::new(s.version);
        for (key, entry) in s.entries.iter().take(3) {
            delta
                .added
                .insert(key.clone(), (entry.clone(), (peer(2), 9_000_000_000)));
        }
        s.merge_delta(&delta, peer(2), Some(&agent(1)))
            .expect("the first delivery merges");
        let canonical = s.retained_image_len().expect("canonical size");
        assert!(
            canonical <= max,
            "the delivered image stays servable: {canonical}"
        );
        let raw_before_replays = bincode::serialized_size(&s).expect("raw size");
        for _ in 0..25 {
            s.merge_delta(&delta, peer(2), Some(&agent(1)))
                .expect("a gossip replay merges at the limit");
        }
        assert_eq!(
            s.retained_image_len().expect("canonical size"),
            canonical,
            "replays grow only bookkeeping, not the canonical image"
        );
        assert_eq!(
            bincode::serialized_size(&s).expect("raw size"),
            raw_before_replays,
            "#1970: the OR-Set changelog is cleared, so replays retain nothing"
        );
    }

    /// #1970 review: a store already past the limit (state merged before
    /// the bound) must still merge removals — that is the only path back to
    /// a servable image. A gate that measures growth from the current size
    /// freezes such a store instead.
    #[test]
    fn a_removal_only_delta_on_an_over_cap_store_recovers() {
        let (mut s, max) = store_within_two_entries_of_the_limit(11, None);
        let value = vec![b'v'; 60_000];
        for i in 0..10u32 {
            s.put(
                format!("r{i:05}"),
                value.clone(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        }
        let over = bincode::serialized_size(&s).expect("size over");
        assert!(over > max, "fixture is past the limit: {over}");
        let mut delta = KvStoreDelta::new(s.version);
        for key in s.entries.keys().take(10).cloned().collect::<Vec<_>>() {
            delta.removed.insert(key, std::collections::HashSet::new());
        }
        s.merge_delta(&delta, peer(1), Some(&agent(1)))
            .expect("a removal-only delta merges into an over-limit store");
        for key in delta.removed.keys() {
            assert!(s.get(key).is_none(), "removed key {key:?} is gone");
        }
        let after = bincode::serialized_size(&s).expect("size after");
        assert!(
            after <= max,
            "the removals recover a servable image: {after}"
        );
    }

    /// #1970 point 1: the admission rule looks at the merged image only.
    /// A retained image whose merge shrinks an over-limit holder but leaves
    /// it above the hard limit is refused, as it would be on a replica that
    /// was never over; one whose merge brings the holder under the limit is
    /// admitted. (The rule of #1996 also admitted any merge that did not grow
    /// the local image, which made the outcome depend on local state.)
    #[test]
    fn the_admission_rule_depends_on_the_merged_image_only() {
        let (mut holder, max) = store_within_two_entries_of_the_limit(12, None);
        let value = vec![b'v'; 60_000];
        for i in 0..40u32 {
            holder
                .put(
                    format!("r{i:05}"),
                    value.clone(),
                    "text/plain".to_string(),
                    peer(1),
                )
                .expect("put");
        }
        let before = holder.retained_image_len().expect("size before");
        assert!(before > max, "fixture is past the limit: {before}");
        let owner = agent(1);
        let mut keys: Vec<String> = holder.entries.keys().cloned().collect();
        keys.sort();
        let shrink = |count: usize| {
            let mut other = KvStore::new_group_signed(
                store_id(12),
                "Wiki".to_string(),
                owner,
                vec![7u8; 16],
                TestCtx::new(7, &[owner]),
            )
            .expect("store");
            for key in keys.iter().take(count) {
                other
                    .put(
                        key.clone(),
                        vec![b's'; 1_000],
                        "text/plain".to_string(),
                        peer(2),
                    )
                    .expect("put");
                other.entries.get_mut(key).expect("entry").updated_at += 10_000;
            }
            other
        };
        let small = shrink(30);
        match holder.merge_group_retained_image(&small, agent(7), peer(2)) {
            Err(KvError::StoreFull { image, .. }) => {
                assert!(image < before, "the merge would have shrunk the holder");
                assert!(image > max, "and left it above the limit: {image}");
            }
            other => panic!("expected StoreFull, got {other:?}"),
        }
        assert_eq!(
            holder.retained_image_len().expect("size"),
            before,
            "nothing of the refused merge applied"
        );
        holder.remove(&keys[keys.len() - 1]).expect("local remove");
        let large = shrink(60);
        holder
            .merge_group_retained_image(&large, agent(7), peer(2))
            .expect("a merge that brings the holder under the limit is admitted");
        assert!(holder.retained_image_len().expect("size") <= max);
        assert_eq!(holder.get(&keys[0]).expect("entry").value.len(), 1_000);
    }

    /// #1970 review round 2 (nit): an over-limit store must judge a MIXED
    /// delta — removals and additions in one message — by its net effect
    /// on the canonical image, not refuse it whole because it carries
    /// adds. The recovery path is exactly this shape: one peer compacts
    /// while another writer adds.
    #[test]
    fn a_mixed_removal_and_add_delta_on_an_over_cap_store_commits() {
        let (mut s, max) = store_within_two_entries_of_the_limit(15, None);
        let value = vec![b'v'; 60_000];
        for i in 0..10u32 {
            s.put(
                format!("r{i:05}"),
                value.clone(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        }
        assert!(
            s.retained_image_len().expect("canonical size") > max,
            "fixture is past the limit"
        );
        let mut delta = KvStoreDelta::new(s.version);
        for key in s.entries.keys().take(10).cloned().collect::<Vec<_>>() {
            delta.removed.insert(key, std::collections::HashSet::new());
        }
        for i in 0..3u32 {
            let key = format!("n{i:05}");
            delta.added.insert(
                key,
                (
                    KvEntry::new(
                        format!("n{i:05}"),
                        vec![b'n'; 1_000],
                        "text/plain".to_string(),
                    ),
                    (peer(2), 8_000_000 + u64::from(i)),
                ),
            );
        }
        s.merge_delta(&delta, peer(2), Some(&agent(1)))
            .expect("a mixed delta whose net effect shrinks the image commits");
        for key in delta.removed.keys() {
            assert!(s.get(key).is_none(), "removed key {key:?} is gone");
        }
        for i in 0..3u32 {
            assert!(
                s.get(&format!("n{i:05}")).is_some(),
                "the delta's addition merged"
            );
        }
        assert!(
            s.retained_image_len().expect("canonical size") <= max,
            "the mixed delta recovered a servable image"
        );
    }

    /// A group store whose roster holds two writers, `agent(1)` (also the
    /// owner) and `agent(2)`.
    pub(super) fn two_writer_group(slot: u8) -> KvStore {
        let owner = agent(1);
        KvStore::new_group_signed(
            store_id(slot),
            "Wiki".to_string(),
            owner,
            vec![7u8; 16],
            TestCtx::new(7, &[owner, agent(2)]),
        )
        .expect("store")
    }

    /// Fill `s` with 60 KB entries by direct puts while the canonical image
    /// stays at or below `target`.
    pub(super) fn fill_canonical_to(
        s: &mut KvStore,
        target: u64,
        prefix: &str,
        writer_peer: PeerId,
    ) {
        for i in 0u32.. {
            if s.retained_image_len().expect("size") + 61_000 > target {
                break;
            }
            s.put(
                format!("{prefix}{i:05}"),
                vec![b'f'; 60_000],
                "text/plain".to_string(),
                writer_peer,
            )
            .expect("put");
        }
    }

    pub(super) fn put_delta(
        key: &str,
        len: usize,
        byte: u8,
        tag: (PeerId, u64),
        version: u64,
    ) -> KvStoreDelta {
        let entry = KvEntry::new(key.to_string(), vec![byte; len], "text/plain".to_string());
        KvStoreDelta::for_put(key.to_string(), entry, tag, version)
    }

    /// The visible state of a replica: each live key with its content and
    /// LWW time, sorted.
    fn visible(s: &KvStore) -> Vec<(String, [u8; 32], u64)> {
        let mut out: Vec<_> = s
            .active_entries()
            .into_iter()
            .map(|e| (e.key.clone(), e.content_hash, e.updated_at))
            .collect();
        out.sort();
        out
    }

    /// Writer `w` on its own replica: put-shaped deltas, each admitted by
    /// the writer's soft-limit gate first, until the gate refuses.
    fn write_until_soft_full(
        replica: &mut KvStore,
        prefix: &str,
        p: PeerId,
        w: AgentId,
    ) -> Vec<KvStoreDelta> {
        let mut deltas = Vec::new();
        for i in 0u64.. {
            let key = format!("{prefix}{i:05}");
            if replica.check_image_room(&key, 60_000, 10, false).is_err() {
                break;
            }
            let d = put_delta(&key, 60_000, b'w', (p, 1_000 + i), replica.version);
            replica.merge_delta(&d, p, Some(&w)).expect("own write");
            deltas.push(d);
        }
        deltas
    }

    fn deliver(r: &mut KvStore, deltas: &[KvStoreDelta], p: PeerId, w: AgentId) {
        for d in deltas {
            r.merge_delta(d, p, Some(&w))
                .expect("admitted within the headroom");
        }
    }

    /// #1970 points 2 and 3: two honest writers that start from a common
    /// state and write concurrently until their own soft-limit gates refuse
    /// stay within the 4 MiB headroom, so every replica admits both, in
    /// either delivery order, and all converge. (With the put gate at the
    /// hard limit, as before, the union passes it and the replicas split.)
    #[test]
    fn concurrent_writes_within_the_headroom_converge_in_either_order() {
        let soft = SOFT_IMAGE_LIMIT_BYTES as u64;
        let hard = HARD_IMAGE_LIMIT_BYTES as u64;
        let mut base = two_writer_group(30);
        fill_canonical_to(&mut base, soft - 1_000_000, "base", peer(3));
        let mut a = base.clone();
        let da = write_until_soft_full(&mut a, "a", peer(1), agent(1));
        let mut b = base.clone();
        let db = write_until_soft_full(&mut b, "b", peer(2), agent(2));
        assert!(!da.is_empty() && !db.is_empty(), "both writers wrote");

        let mut ab = base.clone();
        deliver(&mut ab, &da, peer(1), agent(1));
        deliver(&mut ab, &db, peer(2), agent(2));
        let mut ba = base.clone();
        deliver(&mut ba, &db, peer(2), agent(2));
        deliver(&mut ba, &da, peer(1), agent(1));
        deliver(&mut a, &db, peer(2), agent(2));
        deliver(&mut b, &da, peer(1), agent(1));

        let expected = visible(&ab);
        let size = ab.retained_image_len().expect("size");
        assert!(
            size > soft && size <= hard,
            "the union sits in the headroom: {size}"
        );
        for r in [&ba, &a, &b] {
            assert_eq!(visible(r), expected, "every replica converged");
            assert_eq!(r.retained_image_len().expect("size"), size);
            let status = r.image_status().expect("group store");
            assert_eq!(status.state, crate::kv::ImageState::Full);
            assert_eq!(status.refused_merges, 0);
        }
    }

    /// One delta of `count` 60 KB entries from one writer.
    fn bulk_delta(prefix: &str, count: u64, p: PeerId, version: u64) -> KvStoreDelta {
        let mut d = KvStoreDelta::new(version);
        for i in 0..count {
            let key = format!("{prefix}{i:05}");
            let entry = KvEntry::new(key.clone(), vec![b'z'; 60_000], "text/plain".to_string());
            d.added.insert(key, (entry, (p, 50_000 + i)));
        }
        d
    }

    /// #2068 point 4: a removal by the refused writer of keys only that
    /// writer held does not shrink this replica's image, so the shrink
    /// re-arm does not fire. The writer's delta re-arms its own window,
    /// so this replica retries the writer's image now.
    #[test]
    fn a_removal_from_the_refused_writer_rearms_that_writer() {
        let soft = SOFT_IMAGE_LIMIT_BYTES as u64;
        let mut base = two_writer_group(32);
        fill_canonical_to(&mut base, soft - 500_000, "base", peer(3));
        let da = bulk_delta("a", 50, peer(1), base.version);
        let db = bulk_delta("b", 50, peer(2), base.version);
        let mut ab = base.clone();
        ab.merge_delta(&da, peer(1), Some(&agent(1)))
            .expect("A fits alone");
        assert!(matches!(
            ab.merge_delta(&db, peer(2), Some(&agent(2))),
            Err(KvError::StoreFull { .. })
        ));
        assert!(!ab.image_retry_due(&agent(2)), "B's window is open");
        let before = ab.retained_image_len().expect("size");

        // Writer B removes keys of its own refused delta: none is on this
        // replica.
        let mut removal = KvStoreDelta::new(base.version);
        for i in 0..40u64 {
            removal
                .removed
                .insert(format!("b{i:05}"), std::collections::HashSet::new());
        }
        ab.merge_delta(&removal, peer(2), Some(&agent(2)))
            .expect("a removal is admitted");
        assert!(
            ab.retained_image_len().expect("size") >= before,
            "this replica's image did not shrink"
        );
        assert!(
            ab.image_retry_due(&agent(2)),
            "B's removal re-arms B's retry window"
        );
    }

    /// #1970 point 3: concurrent writes past the headroom (here two 3 MB
    /// deltas that bypass the soft gate) make A-then-B and B-then-A
    /// replicas refuse each other's delta. The refusal is typed, visible
    /// (`full_diverged`, with the refused source) and retried only after a
    /// back-off; one removal re-arms the retry, and the repair merges then
    /// make both replicas converge on the same state.
    #[test]
    fn past_the_headroom_replicas_diverge_visibly_and_one_removal_converges_them() {
        let soft = SOFT_IMAGE_LIMIT_BYTES as u64;
        let hard = HARD_IMAGE_LIMIT_BYTES as u64;
        let mut base = two_writer_group(31);
        fill_canonical_to(&mut base, soft - 500_000, "base", peer(3));
        let da = bulk_delta("a", 50, peer(1), base.version);
        let db = bulk_delta("b", 50, peer(2), base.version);

        let mut ab = base.clone();
        ab.merge_delta(&da, peer(1), Some(&agent(1)))
            .expect("A fits alone");
        let refused = ab.merge_delta(&db, peer(2), Some(&agent(2)));
        assert!(
            matches!(refused, Err(KvError::StoreFull { image, .. }) if image > hard),
            "B is refused after A: {refused:?}"
        );
        let mut ba = base.clone();
        ba.merge_delta(&db, peer(2), Some(&agent(2)))
            .expect("B fits alone");
        let refused = ba.merge_delta(&da, peer(1), Some(&agent(1)));
        assert!(
            matches!(refused, Err(KvError::StoreFull { image, .. }) if image > hard),
            "A is refused after B: {refused:?}"
        );
        assert_ne!(visible(&ab), visible(&ba), "the two orders diverged");
        for (r, source) in [(&ab, agent(2)), (&ba, agent(1))] {
            let status = r.image_status().expect("group store");
            assert_eq!(status.state, crate::kv::ImageState::FullDiverged);
            assert_eq!(status.refused_merges, 1);
            assert_eq!(status.diverged_sources, 1);
            let last = status.last_refusal.expect("last refusal");
            assert_eq!(last.source, hex::encode(source.as_bytes()));
            assert!(last.image_bytes > hard);
            assert!(last.retry_after_ms > last.at_ms, "a retry window is open");
        }

        // A re-delivery is measured again and refused again; this replica's
        // own pulls from the refused writer wait for the retry window.
        assert!(!ab.image_retry_due(&agent(2)));
        let version = ab.version;
        assert!(matches!(
            ab.merge_delta(&db, peer(2), Some(&agent(2))),
            Err(KvError::StoreFull { .. })
        ));
        assert_eq!(ab.version, version, "nothing applied");
        assert_eq!(ab.image_status().expect("status").refused_merges, 2);

        // One removal by writer A, delivered to both replicas.
        let mut base_keys: Vec<String> = base.entries.keys().cloned().collect();
        base_keys.sort();
        let mut removal = KvStoreDelta::new(base.version);
        for key in base_keys.iter().take(40) {
            removal
                .removed
                .insert(key.clone(), std::collections::HashSet::new());
        }
        ab.merge_delta(&removal, peer(1), Some(&agent(1)))
            .expect("a removal is admitted");
        ba.merge_delta(&removal, peer(1), Some(&agent(1)))
            .expect("a removal is admitted");

        // The removal shrank both images, which re-opens the pulls; the
        // repair serves each replica the other's retained image, and the
        // refused delta's content comes back with it.
        assert!(ab.image_retry_due(&agent(2)) && ba.image_retry_due(&agent(1)));
        let ab_image = ab.served_image_for_test();
        let ba_image = ba.served_image_for_test();
        ab.merge_group_retained_image(&ba_image, agent(2), peer(1))
            .expect("the retry converges A-then-B");
        ba.merge_group_retained_image(&ab_image, agent(1), peer(2))
            .expect("the retry converges B-then-A");
        assert_eq!(visible(&ab), visible(&ba), "both orders converged");
        for i in 0..50u64 {
            assert!(
                ab.get(&format!("b{i:05}")).is_some(),
                "B's refused delta recovered"
            );
            assert!(
                ba.get(&format!("a{i:05}")).is_some(),
                "A's refused delta recovered"
            );
        }
        let size = ab.retained_image_len().expect("size");
        assert_eq!(ba.retained_image_len().expect("size"), size);
        assert!(size <= hard);
        for r in [&ab, &ba] {
            let status = r.image_status().expect("status");
            assert_eq!(status.state, crate::kv::ImageState::Full);
            assert_eq!(status.diverged_sources, 0);
        }
    }

    /// #1970 point 4: owner-checkpoint full-snapshot adoption is a merge
    /// into the retained image and is under the same admission rule.
    #[test]
    fn checkpoint_adoption_is_under_the_admission_rule() {
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "x0x/group/adopt";
        let id = KvStoreId::for_topic_owner(topic, &owner);
        let ctx = TestCtx::new(7, &[owner]);
        let mut owner_store =
            KvStore::new_encrypted(id, "S".to_string(), owner, vec![7u8; 16], ctx.clone())
                .expect("owner store");
        for i in 0..290u32 {
            owner_store
                .put(
                    format!("k{i:05}"),
                    vec![b'c'; 60_000],
                    "text/plain".to_string(),
                    peer(1),
                )
                .expect("put");
        }
        let hard = HARD_IMAGE_LIMIT_BYTES as u64;
        assert!(owner_store.retained_image_len().expect("size") > hard);
        let mut relay = owner_store.full_delta().expect("full delta");
        relay.owner_checkpoint = Some(checkpoint_for(&owner_store, topic, &kp, 1));
        let mut joiner =
            KvStore::new_encrypted(id, "S".to_string(), owner, vec![7u8; 16], ctx.clone())
                .expect("joiner");
        let refused = joiner.merge_delta(&relay, peer(9), Some(&agent(9)));
        assert!(
            matches!(refused, Err(KvError::StoreFull { image, .. }) if image > hard),
            "an over-limit snapshot is refused: {refused:?}"
        );
        assert_eq!(joiner.len(), 0, "nothing of it applied");
        assert_eq!(joiner.highest_checkpoint_seq, 0, "no high-water advance");

        for i in 0..40u32 {
            owner_store.remove(&format!("k{i:05}")).expect("remove");
        }
        let mut relay = owner_store.full_delta().expect("full delta");
        relay.owner_checkpoint = Some(checkpoint_for(&owner_store, topic, &kp, 2));
        joiner
            .merge_delta(&relay, peer(9), Some(&agent(9)))
            .expect("a snapshot within the limit is adopted");
        assert_eq!(joiner.highest_checkpoint_seq, 2);
        assert_eq!(joiner.len(), 250);
    }

    /// #1970 points 1 and 5 (review of #2067, findings 1 and 2): the
    /// measure is exactly what the store retains (`bincode` of the store,
    /// the OR-Set changelog included) and what a serve publishes; a key
    /// removed by an image tombstone keeps no value bytes; and the cached
    /// bound the delta fast path keeps never falls below the exact size
    /// and stays close to it through adds, larger and smaller overwrites,
    /// removals, upserts and a removed key that comes back.
    #[test]
    fn the_retained_measure_is_the_stored_bytes_and_the_cached_bound_tracks_it() {
        let mut s = two_writer_group(32);
        for i in 0..20u32 {
            s.put(
                format!("k{i:03}"),
                vec![b'v'; 700 + i as usize],
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        }
        let mut other = s.clone();
        other.remove("k001").expect("remove");
        let image = other.served_image_for_test();
        s.merge_group_retained_image(&image, agent(2), peer(1))
            .expect("merge");
        assert!(
            !s.entries.contains_key("k001"),
            "the removed key's value bytes are gone after the removal merge"
        );
        let check = |s: &KvStore| {
            let retained = s.retained_image_len().expect("measure");
            assert_eq!(retained, bincode::serialized_size(s).expect("stored"));
            assert_eq!(
                retained,
                s.encode_retained_image().expect("serve").len() as u64,
                "the measure is the served image"
            );
            for entry in s.entries.values() {
                assert_eq!(
                    entry.wire_len(),
                    bincode::serialized_size(entry).expect("entry")
                );
            }
            if let Some(cached) = s.image.cached_content(s.version, s.keys.version()) {
                let exact = s.content_len().expect("content");
                assert_eq!(cached, exact, "the cached content length is exact");
            }
        };
        check(&s);
        let mut marked = KvEntry::new("k002".to_string(), vec![b'L'; 3_000], "a/b".to_string());
        marked
            .metadata
            .insert("x0x.writer.agent.v1".to_string(), "ab".repeat(32));
        marked.updated_at += 10_000;
        let mut deltas = vec![
            put_delta("n000", 900, b'n', (peer(2), 1), s.version),
            KvStoreDelta::for_put("k002".to_string(), marked, (peer(2), 2), s.version),
            put_delta("k001", 5, b'r', (peer(2), 4), s.version),
        ];
        // Smaller overwrites: before review of #2067 each one raised the
        // bound by the larger entry's size.
        for i in 0..40u64 {
            deltas.push(put_delta("k003", 10, b's', (peer(2), 100 + i), s.version));
        }
        // Removals: the refreshed bound drops with the removed bytes.
        for i in 4..20u32 {
            let mut removal = KvStoreDelta::new(s.version);
            removal
                .removed
                .insert(format!("k{i:03}"), std::collections::HashSet::new());
            deltas.push(removal);
        }
        let mut upsert = KvStoreDelta::new(s.version);
        upsert.updated.insert(
            "u000".to_string(),
            KvEntry::new("u000".to_string(), vec![b'u'; 40], "text/plain".to_string()),
        );
        deltas.push(upsert);
        s.content_exact().expect("prime the cache");
        for (i, d) in deltas.iter().enumerate() {
            s.merge_delta(d, peer(2), Some(&agent(2)))
                .unwrap_or_else(|e| panic!("delta {i}: {e}"));
            check(&s);
        }
        assert!(s.get("k001").is_some(), "the removed key came back");
        assert!(!s.entries.contains_key("k004"));
    }

    /// #2067 review finding 1: an endorser's image whose entries sit under
    /// keys its OR-Set does not hold (dead on arrival) adds nothing: the
    /// entries are dropped, so neither memory nor the persisted bytes grow,
    /// and the store stays `ok`.
    #[test]
    fn entries_of_dead_keys_in_an_image_are_dropped_not_retained() {
        let mut s = two_writer_group(33);
        s.put(
            "live".to_string(),
            vec![b'v'; 100],
            "text/plain".to_string(),
            peer(1),
        )
        .expect("put");
        let clean = s.served_image_for_test();
        s.merge_group_retained_image(&clean, agent(2), peer(1))
            .expect("a clean image merges");
        let before = s.retained_image_len().expect("size");
        let mut attack = s.served_image_for_test();
        for i in 0..200u32 {
            let key = format!("ghost{i:04}");
            attack.entries.insert(
                key.clone(),
                KvEntry::new(key, vec![b'g'; 60_000], "text/plain".to_string()),
            );
        }
        s.merge_group_retained_image(&attack, agent(2), peer(1))
            .expect("the image merges");
        assert_eq!(s.entries.len(), 1, "no ghost entry is retained");
        assert_eq!(s.retained_image_len().expect("size"), before);
        assert_eq!(bincode::serialized_size(&s).expect("stored"), before);
        assert_eq!(
            s.image_status().expect("status").state,
            crate::kv::ImageState::Ok
        );
    }

    /// #2068 point 2: a stale delta that carries a removed key in
    /// `updated` does not bring it back. The key here was removed by an
    /// image tombstone, so its entry is gone and the update has no live
    /// key to merge into; it is skipped.
    #[test]
    fn a_stale_update_does_not_bring_back_an_image_removed_key() {
        let mut s = two_writer_group(37);
        s.put(
            "k".to_string(),
            vec![b'v'; 100],
            "text/plain".to_string(),
            peer(1),
        )
        .expect("put");
        let stale = s.entries.get("k").expect("entry").clone();
        let mut remover = s.clone();
        remover.keys.remove(&"k".to_string()).expect("remove");
        s.merge_group_retained_image(&remover, agent(2), peer(2))
            .expect("the tombstone image merges");
        assert!(s.get("k").is_none(), "k is removed");
        assert!(!s.entries.contains_key("k"));

        let mut newer = stale;
        newer.updated_at = newer.updated_at.saturating_add(10_000);
        let update = KvStoreDelta::for_update("k".to_string(), newer, s.version);
        s.merge_delta(&update, peer(2), Some(&agent(2)))
            .expect("the update is admitted");
        assert!(
            s.get("k").is_none(),
            "the stale update did not bring k back"
        );
        assert!(!s.entries.contains_key("k"));
        assert!(!s.keys.contains(&"k".to_string()));
    }

    /// #2068 point 6: a real refused merge, reported as `GET /stores`
    /// reports it (`image` is the serialized [`ImageStatus`]), makes
    /// `x0x doctor` warn and name the store; once the repair image merges,
    /// the doctor is quiet again.
    #[test]
    fn a_refused_merge_reaches_the_doctor_warning() {
        use crate::cli::commands::daemon::{store_integrity_check, DoctorCheckStatus};
        let doctor = |s: &KvStore| {
            let image = serde_json::to_value(s.image_status().expect("group store"))
                .expect("status serializes");
            store_integrity_check(&serde_json::json!({ "stores": [
                { "id": "x0x/group/wiki", "durability_degraded": false, "image": image },
            ]}))
        };
        let soft = SOFT_IMAGE_LIMIT_BYTES as u64;
        let mut base = two_writer_group(35);
        fill_canonical_to(&mut base, soft - 500_000, "base", peer(3));
        let da = bulk_delta("a", 50, peer(1), base.version);
        let db = bulk_delta("b", 50, peer(2), base.version);
        let mut ab = base.clone();
        ab.merge_delta(&da, peer(1), Some(&agent(1)))
            .expect("A fits alone");
        assert_eq!(
            doctor(&ab).status,
            DoctorCheckStatus::Ok,
            "full is not a warning"
        );
        assert!(ab.merge_delta(&db, peer(2), Some(&agent(2))).is_err());
        let check = doctor(&ab);
        assert_eq!(check.status, DoctorCheckStatus::Warn, "{}", check.detail);
        assert!(
            check.detail.contains("x0x/group/wiki (full_diverged)"),
            "{}",
            check.detail
        );

        let mut base_keys: Vec<String> = base.entries.keys().cloned().collect();
        base_keys.sort();
        let mut removal = KvStoreDelta::new(base.version);
        for key in base_keys.iter().take(40) {
            removal
                .removed
                .insert(key.clone(), std::collections::HashSet::new());
        }
        let mut b = base.clone();
        b.merge_delta(&db, peer(2), Some(&agent(2)))
            .expect("B fits alone");
        b.merge_delta(&removal, peer(1), Some(&agent(1)))
            .expect("a removal is admitted");
        ab.merge_delta(&removal, peer(1), Some(&agent(1)))
            .expect("a removal is admitted");
        ab.merge_group_retained_image(&b.served_image_for_test(), agent(2), peer(1))
            .expect("the repair image merges");
        let check = doctor(&ab);
        assert_eq!(check.status, DoctorCheckStatus::Ok, "{}", check.detail);
    }

    /// #2068 point 6: a peer on a version before #1970 serves its raw
    /// image, which still holds the entries of keys it removed (and here a
    /// newer value under one of them). The receiver applies the removal,
    /// drops those entries, and neither resurrects the key nor retains
    /// their bytes.
    #[test]
    fn an_old_peers_image_with_removed_keys_entries_retains_nothing_dead() {
        let mut s = two_writer_group(36);
        for i in 0..20u32 {
            s.put(
                format!("k{i:02}"),
                vec![b'v'; 1_000],
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        }
        let mut old = s.clone();
        for i in 0..10u32 {
            let key = format!("k{i:02}");
            old.keys.remove(&key).expect("remove");
            let mut kept = KvEntry::new(key.clone(), vec![b'o'; 60_000], "text/plain".to_string());
            kept.updated_at = u64::MAX / 2;
            old.entries.insert(key, kept);
        }
        assert_eq!(old.entries.len(), 20, "the old peer kept every entry");
        s.merge_group_retained_image(&old, agent(2), peer(2))
            .expect("the old image merges");
        for i in 0..10u32 {
            let key = format!("k{i:02}");
            assert!(s.get(&key).is_none(), "{key} stays removed");
            assert!(!s.entries.contains_key(&key), "{key}'s entry is dropped");
        }
        assert_eq!(s.entries.len(), 10);
        let mut settled = s.clone();
        settled.settle_retained(None, &mut EntryJournal::default());
        assert_eq!(
            s.retained_image_len().expect("size"),
            settled.retained_image_len().expect("size"),
            "nothing dead is retained"
        );
        assert!(s.retained_image_len().expect("size") < 60_000);
    }

    /// #2067 review finding 5: the per-replica fields (here a history
    /// endorser) differ between two replicas that hold the same replicated
    /// state, but the admission size does not, so their decisions agree.
    #[test]
    fn replicas_with_different_local_fields_measure_the_same_admission_size() {
        let mut a = two_writer_group(34);
        a.put(
            "k".to_string(),
            vec![b'v'; 100],
            "text/plain".to_string(),
            peer(1),
        )
        .expect("put");
        let mut b = a.clone();
        b.last_history_endorser = Some(agent(9));
        b.ownership_conflict = Some((agent(1), agent(9)));
        assert_ne!(
            a.retained_image_len().expect("a"),
            b.retained_image_len().expect("b"),
            "the replicas retain different local bytes"
        );
        assert_eq!(
            a.admission_image_len().expect("a"),
            b.admission_image_len().expect("b"),
            "and measure the same admission size"
        );
    }

    /// #2067 review findings 2 and 4: after a removal that only one replica
    /// holds, the other replica admits the shrunk image as soon as it is
    /// offered. A back-off never refuses an incoming merge; it only delays
    /// this replica's own pulls (see the pull-gate test below).
    #[test]
    fn a_removal_known_to_one_replica_only_is_admitted_once_offered() {
        let soft = SOFT_IMAGE_LIMIT_BYTES as u64;
        let mut base = two_writer_group(35);
        fill_canonical_to(&mut base, soft - 500_000, "base", peer(3));
        let mut a = base.clone();
        a.merge_delta(
            &bulk_delta("a", 50, peer(1), a.version),
            peer(1),
            Some(&agent(1)),
        )
        .expect("A writes");
        let mut b = base.clone();
        b.merge_delta(
            &bulk_delta("b", 50, peer(2), b.version),
            peer(2),
            Some(&agent(2)),
        )
        .expect("B writes");
        assert!(matches!(
            b.merge_group_retained_image(&a.served_image_for_test(), agent(1), peer(2)),
            Err(KvError::StoreFull { .. })
        ));
        assert!(!b.image_retry_due(&agent(1)), "B's pulls from A back off");
        // A removes its own keys, which B never held.
        for i in 0..45u64 {
            a.remove(&format!("a{i:05}")).expect("remove");
        }
        b.merge_group_retained_image(&a.served_image_for_test(), agent(1), peer(2))
            .expect("B measures A's shrunk image and takes it at once");
        assert!(b.image_retry_due(&agent(1)), "the record of A is cleared");
        a.merge_group_retained_image(&b.served_image_for_test(), agent(2), peer(1))
            .expect("A takes B's image");
        assert_eq!(visible(&a), visible(&b), "both replicas converged");
    }

    /// #2067 re-review: the pull gate. After B refuses A's image, B's pulls
    /// from A are deferred (`image_retry_due` is false, so the digest-beacon
    /// wake is not granted). A's removal of keys only A held does not shrink
    /// B's image, so B waits for the window; once it has passed the pull is
    /// due, and the merge of A's shrunk image converges.
    #[test]
    fn the_pull_gate_defers_a_refused_source_until_its_window_passes() {
        let soft = SOFT_IMAGE_LIMIT_BYTES as u64;
        let mut base = two_writer_group(36);
        fill_canonical_to(&mut base, soft - 500_000, "base", peer(3));
        let mut a = base.clone();
        a.merge_delta(
            &bulk_delta("a", 50, peer(1), a.version),
            peer(1),
            Some(&agent(1)),
        )
        .expect("A writes");
        let mut b = base.clone();
        b.merge_delta(
            &bulk_delta("b", 50, peer(2), b.version),
            peer(2),
            Some(&agent(2)),
        )
        .expect("B writes");
        assert!(matches!(
            b.merge_group_retained_image(&a.served_image_for_test(), agent(1), peer(2)),
            Err(KvError::StoreFull { .. })
        ));
        for i in 0..45u64 {
            a.remove(&format!("a{i:05}")).expect("remove");
        }
        let now = now_ms();
        assert!(!b.image_retry_due(&agent(1)), "the pull from A is deferred");
        assert!(
            !b.image.retry_due(&agent(1), now + 29_000),
            "still deferred inside the first 30 s window"
        );
        assert!(
            b.image.retry_due(&agent(1), now + 31_000),
            "due once the window has passed"
        );
        b.merge_group_retained_image(&a.served_image_for_test(), agent(1), peer(2))
            .expect("the due pull converges");
        a.merge_group_retained_image(&b.served_image_for_test(), agent(2), peer(1))
            .expect("A takes B's image");
        assert_eq!(visible(&a), visible(&b));
    }

    /// #1970 review round 2 (nit): only stores that serve their complete
    /// state as a retained group image live under the retained-image
    /// limit. An owner-anchored Signed store serves deltas, not retained
    /// images, so its merges stay unbounded by the retained-image cap.
    #[test]
    fn a_non_retained_store_merges_past_the_retained_image_limit() {
        let owner = agent(1);
        let mut s = KvStore::new(
            store_id(20),
            "Logs".to_string(),
            owner,
            AccessPolicy::Signed,
        )
        .expect("store");
        let value = vec![b'v'; 60_000];
        for i in 0..300u32 {
            s.put(
                format!("k{i:05}"),
                value.clone(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        }
        let mut delta = KvStoreDelta::new(s.version);
        for i in 0..10u32 {
            let key = format!("d{i:05}");
            delta.added.insert(
                key,
                (
                    KvEntry::new(format!("d{i:05}"), value.clone(), "text/plain".to_string()),
                    (peer(2), 7_000_000 + u64::from(i)),
                ),
            );
        }
        s.merge_delta(&delta, peer(2), Some(&owner))
            .expect("a Signed store merges without the retained-image bound");
        assert!(
            bincode::serialized_size(&s).expect("size")
                > crate::kv::retained_paging::MAX_RETAINED_IMAGE_BYTES as u64,
            "a store that never serves a retained image is not refused for its size"
        );
    }

    /// #1970 review round 2: the canonical measure's field-swapping
    /// arithmetic (`size − keys + canonical keys`) must equal the
    /// serialized size of a real canonicalized copy — bincode concatenates
    /// a struct's fields with no cross-field framing. This pins the
    /// invariant the merge bound's cheap measure relies on, and that the
    /// canonical form round-trips for every existing receiver.
    #[test]
    fn the_canonical_measure_equals_a_canonicalized_copy() {
        let owner = agent(1);
        let mut s = KvStore::new_group_signed(
            store_id(21),
            "Wiki".to_string(),
            owner,
            vec![7u8; 16],
            TestCtx::new(7, &[owner]),
        )
        .expect("store");
        for i in 0..25u32 {
            s.put(
                format!("k{i:03}"),
                vec![b'v'; 500],
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        }
        s.remove("k000").expect("tombstone");
        let mut replayed = KvStoreDelta::new(s.version);
        for (key, entry) in s.entries.iter().take(5) {
            replayed
                .added
                .insert(key.clone(), (entry.clone(), (peer(2), 123)));
        }
        s.merge_delta(&replayed, peer(2), Some(&agent(1)))
            .expect("re-delivery");
        let measured = s.retained_image_len().expect("measured");
        let copy = s.served_image_for_test();
        let copy_size = bincode::serialized_size(&copy).expect("copy size");
        assert_eq!(
            measured, copy_size,
            "the measure is exactly the canonical copy's size"
        );
        let raw = bincode::serialized_size(&s).expect("raw size");
        assert_eq!(
            raw, measured,
            "#1970: the measure is what the store retains, changelog included"
        );
        let wire = bincode::serialize(&copy).expect("wire");
        let back: KvStore = bincode::deserialize(&wire).expect("round trip");
        assert_eq!(
            back.entries.len(),
            s.entries.len(),
            "content survives the wire form"
        );
    }

    /// #1970 review round 2 (nit): a refused retained-image merge applies
    /// NOTHING — not even raising the shared sequence allocator that the
    /// trial's `restore_seq_counter` would move — while a committing
    /// merge of the same image still applies the floor.
    #[test]
    fn a_refused_retained_image_merge_leaves_the_sequence_allocator_untouched() {
        let (mut holder, max) = store_within_two_entries_of_the_limit(22, None);
        let value = vec![b'v'; 60_000];
        for i in 0..10u32 {
            holder
                .put(
                    format!("r{i:05}"),
                    value.clone(),
                    "text/plain".to_string(),
                    peer(1),
                )
                .expect("put");
        }
        assert!(
            bincode::serialized_size(&holder).expect("size") > max,
            "fixture is past the limit"
        );
        let owner = agent(1);
        // A same-binding image whose tags for the local peer run past the
        // holder's own counter, so a committing merge must raise the
        // allocator to its floor.
        let mut other = KvStore::new_group_signed(
            store_id(22),
            "Wiki".to_string(),
            owner,
            vec![7u8; 16],
            TestCtx::new(7, &[owner]),
        )
        .expect("store");
        for i in 0..5_000u32 {
            other
                .put(
                    format!("p{i:04}"),
                    vec![0; 1],
                    "text/plain".to_string(),
                    peer(3),
                )
                .expect("put");
        }
        let floor = other
            .keys
            .max_retained_sequence_for_peer(&peer(3))
            .expect("floor");
        let before = holder.seq_counter_value();
        assert!(
            floor > before,
            "the image's floor sits above the holder's counter: {floor} vs {before}"
        );
        match holder.merge_group_retained_image(&other, agent(7), peer(3)) {
            Err(KvError::StoreFull { .. }) => {}
            other_result => panic!("expected a typed StoreFull refusal, got {other_result:?}"),
        }
        assert_eq!(
            holder.seq_counter_value(),
            before,
            "the refused merge raised nothing — not even the sequence allocator"
        );
        // Control: a committing merge of the same image applies the floor.
        let mut small = KvStore::new_group_signed(
            store_id(22),
            "Wiki".to_string(),
            owner,
            vec![7u8; 16],
            TestCtx::new(7, &[owner]),
        )
        .expect("store");
        small
            .put(
                "s".to_string(),
                vec![b's'; 100],
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let small_before = small.seq_counter_value();
        small
            .merge_group_retained_image(&other, agent(7), peer(3))
            .expect("a committing merge");
        assert!(
            small.seq_counter_value() >= floor && small.seq_counter_value() > small_before,
            "a committing merge still raises the allocator to the image's floor"
        );
    }

    /// Positive control: far from the limit, an ordinary growth delta still
    /// merges — the bound refuses only growth past the limit.
    #[test]
    fn an_under_limit_delta_merges() {
        let owner = agent(1);
        let mut s = KvStore::new_group_signed(
            store_id(13),
            "Wiki".to_string(),
            owner,
            vec![7u8; 16],
            TestCtx::new(7, &[owner]),
        )
        .expect("store");
        for i in 0..10u32 {
            s.put(
                format!("k{i:05}"),
                vec![b'v'; 1_000],
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        }
        let mut delta = KvStoreDelta::new(s.version);
        for i in 0..5u32 {
            delta.added.insert(
                format!("n{i:05}"),
                (
                    KvEntry::new(
                        format!("n{i:05}"),
                        vec![b'n'; 1_000],
                        "text/plain".to_string(),
                    ),
                    (peer(2), i as u64 + 100),
                ),
            );
        }
        s.merge_delta(&delta, peer(2), Some(&agent(1)))
            .expect("an under-limit delta merges");
        assert_eq!(s.entries.len(), 15, "every entry applied");
    }

    /// Coverage (#1970 review): the merge bound covers every store kind
    /// that serves a retained image — Encrypted and TreeKemEncrypted take
    /// the same typed refusal as GroupSigned.
    #[test]
    fn the_bound_covers_encrypted_and_treekem_stores() {
        for encrypted in [Some(false), Some(true)] {
            let (mut s, max) = store_within_two_entries_of_the_limit(14, encrypted);
            let mut delta = KvStoreDelta::new(s.version);
            for i in 0..3u32 {
                delta.added.insert(
                    format!("z{i:05}"),
                    (
                        KvEntry::new(
                            format!("z{i:05}"),
                            vec![b'z'; 60_000],
                            "text/plain".to_string(),
                        ),
                        (peer(2), i as u64 + 100),
                    ),
                );
            }
            match s.merge_delta(&delta, peer(2), Some(&agent(1))) {
                Err(KvError::StoreFull { image, .. }) => assert!(image > max),
                other => panic!("expected a typed StoreFull refusal, got {other:?}"),
            }
        }
    }

    /// Socket-free characterization of retained-image paging (issue-802
    /// mechanism, NOT a live-R8 reproduction): the positive control proves
    /// complementary single-frame loss retries assemble a stable image; the
    /// repaired retry proves an idempotent sender self-merge preserves the
    /// complete image_id so the receiver can use buffered pages.
    mod retained_paging_characterization {
        use super::*;
        use crate::kv::retained_paging::{
            decode_page, split_image, RetainedPageBinding, RetainedPagePool, RetainedPageV1,
        };

        /// Decode a serialized image into frames: `frames[0]` is the
        /// manifest, `frames[k]` is data page index `k - 1`.
        fn paged_frames(image: &[u8]) -> Vec<RetainedPageV1> {
            let decoded: Vec<_> = split_image(image, 512)
                .expect("split")
                .iter()
                .map(|f| decode_page(f).expect("decode").expect("paged frame"))
                .collect();
            assert!(decoded.len() > 3, "image must span multiple page frames");
            decoded
        }

        fn image_id_of(frames: &[RetainedPageV1]) -> [u8; 32] {
            match frames[0] {
                RetainedPageV1::Manifest { image_id, .. } => image_id,
                RetainedPageV1::Page { .. } => panic!("manifest first"),
            }
        }

        /// GroupSigned sender whose serialized image spans multiple
        /// retained frames: (store, serialized image, decoded frames).
        fn paged_group_signed_sender(slot: u8) -> (KvStore, Vec<u8>, Vec<RetainedPageV1>) {
            let owner = agent(1);
            let mut sender = KvStore::new_group_signed(
                store_id(slot),
                "Wiki".to_string(),
                owner,
                vec![7u8; 16],
                TestCtx::new(7, &[owner]),
            )
            .expect("sender");
            for tag in 0..4u8 {
                sender
                    .put(
                        format!("page-{tag}"),
                        vec![b'a' + tag; 512],
                        "text/plain".to_string(),
                        peer(1),
                    )
                    .expect("seed page");
            }
            let image = bincode::serialize(&sender).expect("retained image");
            let frames = paged_frames(&image);
            (sender, image, frames)
        }

        fn retained_binding(slot: u8, image_id: [u8; 32]) -> RetainedPageBinding {
            RetainedPageBinding {
                store_id: [slot; 32],
                endorser: *agent(1).as_bytes(),
                authorization: [7; 32],
                image_id,
            }
        }

        /// One serve round: the manifest is ALWAYS delivered; exactly one
        /// data page (index `omit_page`) is lost.
        fn deliver_round(
            pool: &mut RetainedPagePool,
            binding: &RetainedPageBinding,
            frames: &[RetainedPageV1],
            omit_page: usize,
        ) -> Option<Vec<u8>> {
            let mut completed = None;
            for frame in frames {
                if let RetainedPageV1::Page { index, .. } = frame {
                    if *index as usize == omit_page {
                        continue;
                    }
                }
                completed = pool
                    .push(binding.clone(), frame.clone())
                    .expect("delivered frame")
                    .or(completed);
            }
            completed
        }

        #[test]
        fn retained_image_completes_from_complementary_single_frame_loss_retries() {
            let (_sender, image, frames) = paged_group_signed_sender(23);
            let binding = retained_binding(23, image_id_of(&frames));
            let mut pool = RetainedPagePool::default();
            // Retry 1 loses exactly one data page (index 0); manifest
            // delivered, image stranded.
            assert!(deliver_round(&mut pool, &binding, &frames, 0).is_none());
            // Retry 2 loses a DIFFERENT single data page (index 1): its
            // page index 0 plus the buffered pages complete the image.
            let assembled = deliver_round(&mut pool, &binding, &frames, 1)
                .expect("complementary retries assemble the image");
            assert_eq!(assembled, image);

            let image_store: KvStore = bincode::deserialize(&assembled).expect("image decode");
            let owner = agent(1);
            let mut target = KvStore::new_group_signed(
                store_id(23),
                "Wiki".to_string(),
                owner,
                vec![7u8; 16],
                TestCtx::new(7, &[owner]),
            )
            .expect("target");
            target
                .merge_group_retained_image(&image_store, owner, peer(9))
                .expect("assembled image merges into a group-signed replica");
            for tag in 0..4u8 {
                assert_eq!(
                    target.get(&format!("page-{tag}")).expect("page").value,
                    vec![b'a' + tag; 512]
                );
            }
        }

        #[test]
        fn retained_self_merge_keeps_image_id_and_completes_complementary_pages() {
            let (mut sender, initial_image, _) = paged_group_signed_sender(24);
            // The first authenticated endorsement is a real audit change.
            // Establish it before testing a retry from the same endorser.
            let initial_store: KvStore =
                bincode::deserialize(&initial_image).expect("initial image");
            let version_before_endorsement = sender.current_version();
            sender
                .merge_group_retained_image(&initial_store, agent(1), peer(1))
                .expect("first endorsement");
            assert!(sender.current_version() > version_before_endorsement);
            assert_eq!(sender.last_history_endorser(), Some(&agent(1)));
            let image_one = bincode::serialize(&sender).expect("first endorsed image");
            let frames_one = paged_frames(&image_one);
            let binding_one = retained_binding(24, image_id_of(&frames_one));
            let digest_before = sender.served_digest();
            let version_before = sender.current_version();
            let mut pool = RetainedPagePool::default();
            // Same omission schedule as the stable arm: manifest plus every
            // data page except page index 0.
            assert!(deliver_round(&mut pool, &binding_one, &frames_one, 0).is_none());

            // Between retries the sender merges its own complete current
            // image from the same endorser. No retained state changes.
            let self_image: KvStore = bincode::deserialize(&image_one).expect("own image");
            sender
                .merge_group_retained_image(&self_image, agent(1), peer(1))
                .expect("self merge");
            assert_eq!(
                sender.served_digest(),
                digest_before,
                "idempotent self-merge leaves active content unchanged"
            );
            assert_eq!(sender.current_version(), version_before);
            let image_two = bincode::serialize(&sender).expect("second image");
            assert_eq!(
                image_two, image_one,
                "same retained image stays byte-stable"
            );
            let frames_two = paged_frames(&image_two);
            let binding_two = retained_binding(24, image_id_of(&frames_two));
            assert_eq!(binding_two.image_id, binding_one.image_id);

            // Retry 2 omits page index 1 but supplies the missing page 0;
            // pages from both rounds now bind to the same complete image.
            let assembled = deliver_round(&mut pool, &binding_two, &frames_two, 1)
                .expect("complementary pages assemble after same-endorser replay");
            assert_eq!(assembled, image_one);
        }

        #[test]
        fn retained_endorser_change_versions_once_and_same_writer_replay_does_not() {
            let owner = agent(1);
            let next_writer = agent(2);
            let mut store = KvStore::new_group_signed(
                store_id(25),
                "Wiki".to_string(),
                owner,
                vec![7u8; 16],
                TestCtx::new(7, &[owner, next_writer]),
            )
            .expect("store");
            store
                .put(
                    "page".to_string(),
                    b"value".to_vec(),
                    "text/plain".to_string(),
                    peer(1),
                )
                .expect("page");
            let image: KvStore =
                bincode::deserialize(&bincode::serialize(&store).expect("wire")).expect("image");
            let before_first = store.current_version();
            store
                .merge_group_retained_image(&image, owner, peer(1))
                .expect("first current writer endorsement");
            assert!(store.current_version() > before_first);
            assert_eq!(store.last_history_endorser(), Some(&owner));

            let before_replay = store.current_version();
            store
                .merge_group_retained_image(&image, owner, peer(1))
                .expect("same current writer replay");
            assert_eq!(store.current_version(), before_replay);

            store
                .merge_group_retained_image(&image, next_writer, peer(1))
                .expect("new current writer endorsement");
            assert!(store.current_version() > before_replay);
            assert_eq!(store.last_history_endorser(), Some(&next_writer));
            let before_new_replay = store.current_version();
            store
                .merge_group_retained_image(&image, next_writer, peer(1))
                .expect("new current writer replay");
            assert_eq!(store.current_version(), before_new_replay);
        }

        #[test]
        fn retained_unseen_tombstone_versions_with_equal_active_digest_and_floors_seq() {
            let owner = agent(1);
            let local_peer = peer(4);
            let context = TestCtx::new(7, &[owner]);
            let mut source = KvStore::new_group_signed(
                store_id(26),
                "Wiki".to_string(),
                owner,
                vec![7u8; 16],
                context.clone(),
            )
            .expect("source");
            source
                .put(
                    "removed".to_string(),
                    b"old".to_vec(),
                    "text/plain".to_string(),
                    local_peer,
                )
                .expect("old value");
            let stale = source.clone();
            source.remove("removed").expect("tombstone");
            let mut target = KvStore::new_group_signed(
                store_id(26),
                "Wiki".to_string(),
                owner,
                vec![7u8; 16],
                context,
            )
            .expect("target");
            // Match every retained entry field while deliberately lacking
            // the OR-Set tag/tombstone. Only causal state can trigger change.
            target.entries = source.entries.clone();
            let initial: KvStore =
                bincode::deserialize(&bincode::serialize(&target).expect("initial wire"))
                    .expect("initial image");
            target
                .merge_group_retained_image(&initial, owner, local_peer)
                .expect("establish same endorser");
            assert_eq!(target.served_digest(), source.served_digest());
            let before = target.current_version();
            target
                .merge_group_retained_image(&source, owner, local_peer)
                .expect("new tombstone");
            assert!(target.current_version() > before, "causal change versions");
            assert!(target.get("removed").is_none());
            let floor = source
                .keys
                .max_retained_sequence_for_peer(&local_peer)
                .expect("tombstone sequence");
            assert_eq!(target.seq_counter_value(), floor);

            let mut restored: KvStore =
                bincode::deserialize(&bincode::serialize(&target).expect("retained wire"))
                    .expect("retained roundtrip");
            restored
                .merge_group_retained_image(&stale, owner, local_peer)
                .expect("stale add replay");
            assert!(
                restored.get("removed").is_none(),
                "tombstone blocks old tag"
            );
            assert!(restored.next_seq().expect("floored sequence") > floor);
        }
    }

    #[test]
    fn retained_import_floors_same_peer_sequence_above_tombstones() {
        let owner = agent(1);
        let ctx = TestCtx::new(7, &[owner]);
        let id = store_id(18);
        let group = vec![7u8; 16];
        let local_peer = peer(4);
        let mut source =
            KvStore::new_group_signed(id, "Wiki".to_string(), owner, group.clone(), ctx.clone())
                .expect("source");
        source
            .put(
                "page".to_string(),
                b"old".to_vec(),
                "text/plain".to_string(),
                local_peer,
            )
            .expect("source put");
        source.remove("page").expect("source remove");
        let encoded = bincode::serialize(&source).expect("retained wire image");
        let source: KvStore = bincode::deserialize(&encoded).expect("fresh retained decode");
        assert_eq!(source.seq_counter_value(), 0, "wire image skips allocator");

        let mut target = KvStore::new_group_signed(id, "Wiki".to_string(), owner, group, ctx)
            .expect("independent target");
        target
            .merge_group_retained_image(&source, owner, local_peer)
            .expect("authenticated retained merge");
        assert_eq!(
            target.seq_counter_value(),
            source
                .keys
                .max_retained_sequence_for_peer(&local_peer)
                .expect("source retained sequence"),
            "allocator is restored to the imported retained-tag ceiling"
        );
        target
            .put(
                "page".to_string(),
                b"new".to_vec(),
                "text/plain".to_string(),
                local_peer,
            )
            .expect("re-add after imported tombstone");
        assert_eq!(target.get("page").expect("re-add visible").value, b"new");
        target.remove("page").expect("remove re-add");
        target
            .put(
                "page".to_string(),
                b"newer".to_vec(),
                "text/plain".to_string(),
                local_peer,
            )
            .expect("second re-add");
        assert_eq!(
            target.get("page").expect("second re-add visible").value,
            b"newer"
        );
    }

    #[test]
    fn retained_import_rejects_exhausted_same_peer_sequence_transactionally() {
        let owner = agent(1);
        let ctx = TestCtx::new(7, &[owner]);
        let id = store_id(19);
        let group = vec![7u8; 16];
        let local_peer = peer(4);
        let mut source =
            KvStore::new_group_signed(id, "Wiki".to_string(), owner, group.clone(), ctx.clone())
                .expect("source");
        source
            .put(
                "page".to_string(),
                b"old".to_vec(),
                "text/plain".to_string(),
                local_peer,
            )
            .expect("source put");
        source
            .keys
            .add("page".to_string(), (local_peer, u64::MAX - 1))
            .expect("near-exhausted retained tag");

        let mut target =
            KvStore::new_group_signed(id, "Wiki".to_string(), owner, group, ctx).expect("target");
        let before = bincode::serialize(&target).expect("before");
        assert!(matches!(
            target.merge_group_retained_image(&source, owner, local_peer),
            Err(KvError::Merge(message)) if message.contains("allocator capacity")
        ));
        assert_eq!(bincode::serialize(&target).expect("after"), before);
        assert_eq!(target.seq_counter_value(), 0);
    }

    #[test]
    fn full_delta_fails_closed_when_synthetic_tags_would_exhaust_allocator() {
        let owner = agent(1);
        let mut store = KvStore::new(
            store_id(20),
            "store".to_string(),
            owner,
            AccessPolicy::Signed,
        )
        .expect("store");
        store
            .put(
                "page".to_string(),
                b"value".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        store.restore_seq_counter(u64::MAX);
        let before = bincode::serialize(&store).expect("before");
        assert!(matches!(store.full_delta(), Err(KvError::Merge(_))));
        assert_eq!(bincode::serialize(&store).expect("after"), before);
        assert_eq!(store.seq_counter_value(), u64::MAX);
    }

    #[test]
    fn encrypted_retained_image_preserves_removal_and_concurrent_write() {
        let owner = agent(1);
        let writer = agent(2);
        let ctx = TestCtx::new(7, &[owner, writer]);
        let id = store_id(10);
        let group = vec![7u8; 16];
        let mut source =
            KvStore::new_encrypted(id, "Home".to_string(), owner, group.clone(), ctx.clone())
                .expect("source");
        source
            .put(
                "removed".to_string(),
                b"old".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("seed");
        let mut target = source.clone();
        source.remove("removed").expect("remove");
        target
            .put(
                "concurrent".to_string(),
                b"local".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("concurrent");

        target
            .merge_group_retained_image(&source, writer, peer(2))
            .expect("authenticated retained image");
        assert!(target.get("removed").is_none());
        assert_eq!(
            target.get("concurrent").expect("concurrent survives").value,
            b"local"
        );
        assert_eq!(target.last_history_endorser(), Some(&writer));
        assert!(matches!(
            target.policy(),
            AccessPolicy::Encrypted { group_id } if group_id == &group
        ));

        let mut unauthenticated = source.clone();
        unauthenticated.allowed_writers.insert(agent(9));
        let before = target.clone();
        assert!(target.merge(&unauthenticated).is_err());
        assert_eq!(target.name(), before.name());
        assert_eq!(target.len(), before.len());
        assert_eq!(target.allowed_writers(), before.allowed_writers());
        assert!(target.get("concurrent").is_some());

        let mut treekem = KvStore::new_treekem_encrypted(
            id,
            "Home".to_string(),
            owner,
            group,
            TestCtx::new(7, &[owner, writer]),
        )
        .expect("TreeKEM target");
        treekem
            .put(
                "private".to_string(),
                b"keep".to_vec(),
                "text/plain".to_string(),
                peer(3),
            )
            .expect("TreeKEM local write");
        assert!(treekem
            .merge_group_retained_image(&source, writer, peer(3))
            .is_err());
        assert_eq!(
            treekem.get("private").expect("local remains").value,
            b"keep",
            "a legacy GSS image cannot cross into the TreeKEM plane"
        );
        assert!(treekem.get("removed").is_none());
    }

    #[test]
    fn legacy_signed_import_is_content_only_and_retry_idempotent() {
        let source_owner = agent(1);
        let writer = agent(2);
        let mut source = KvStore::new(
            store_id(21),
            "Legacy Wiki".to_string(),
            source_owner,
            AccessPolicy::Signed,
        )
        .expect("legacy source");
        source
            .put(
                "removed".to_string(),
                b"old".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("seed removed key");
        source.remove("removed").expect("source tombstone");
        source
            .put(
                "imported".to_string(),
                b"history".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("seed imported key");
        source
            .put(
                "shared".to_string(),
                b"legacy".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("seed conflicting key");
        source
            .entries
            .get_mut("imported")
            .expect("imported metadata target")
            .metadata
            .extend([
                ("z-last".to_string(), "second".to_string()),
                ("a-first".to_string(), "first".to_string()),
            ]);
        let encoded = bincode::serialize(&source).expect("legacy snapshot");
        let source: KvStore = bincode::deserialize(&encoded).expect("restart decode");
        assert_eq!(source.seq_counter_value(), 0, "allocator is not serialized");

        let group = vec![9u8; 16];
        let mut destination = KvStore::new_group_signed(
            store_id(22),
            "Wiki".to_string(),
            writer,
            group.clone(),
            TestCtx::new(9, &[writer]),
        )
        .expect("destination");
        destination
            .put(
                "concurrent".to_string(),
                b"keep".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("local value");
        destination
            .put(
                "shared".to_string(),
                b"current".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("current conflicting key");

        assert_eq!(
            destination.legacy_import_conflicts(&source),
            vec!["shared".to_string()]
        );

        let mut forged = source.clone();
        let wrong_entry = forged.get("imported").expect("entry").clone();
        forged
            .entries
            .insert("wrong-map-key".to_string(), wrong_entry);
        let before_forged = bincode::serialize(&destination).expect("before forged import");
        assert!(destination
            .merge_legacy_signed_history(&forged, source_owner, writer, peer(2))
            .is_err());
        assert_eq!(
            bincode::serialize(&destination).expect("after forged import"),
            before_forged,
            "invalid source rejection is transactionally unchanged"
        );

        destination
            .merge_legacy_signed_history(&source, source_owner, writer, peer(2))
            .expect("first import");
        let first_counter = destination.seq_counter_value();
        let first_version = destination.current_version();
        assert!(destination.get("removed").is_none());
        assert_eq!(
            destination.get("imported").expect("imported").value,
            b"history"
        );
        assert_eq!(destination.get("concurrent").expect("local").value, b"keep");
        assert_eq!(destination.owner(), Some(&writer));
        assert_eq!(destination.last_history_endorser(), Some(&writer));
        assert!(matches!(
            destination.policy(),
            AccessPolicy::GroupSigned { group_id } if group_id == &group
        ));
        let encoded_retry = bincode::serialize(&source).expect("retry snapshot");
        let mut reordered_source: KvStore =
            bincode::deserialize(&encoded_retry).expect("retry restart decode");
        let mut reordered_entries = HashMap::new();
        let mut entry_keys = reordered_source.entries.keys().cloned().collect::<Vec<_>>();
        entry_keys.sort_by(|left, right| right.cmp(left));
        for key in entry_keys {
            let mut entry = reordered_source.entries.remove(&key).expect("retry entry");
            let mut metadata = entry.metadata.drain().collect::<Vec<_>>();
            metadata.sort_by(|left, right| right.0.cmp(&left.0));
            entry.metadata.extend(metadata);
            reordered_entries.insert(key, entry);
        }
        reordered_source.entries = reordered_entries;
        destination
            .merge_legacy_signed_history(&reordered_source, source_owner, writer, peer(2))
            .expect("restart/reordered receipt-failure retry");
        assert_eq!(destination.seq_counter_value(), first_counter);
        assert_eq!(
            destination.current_version(),
            first_version,
            "logically identical retry does not advance the destination"
        );

        destination
            .put(
                "removed".to_string(),
                b"re-added".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("re-add after imported same-peer tombstone");
        assert_eq!(
            destination.get("removed").expect("re-add visible").value,
            b"re-added"
        );
    }

    #[test]
    fn generic_merge_rejects_group_signed_state_without_endorser() {
        let owner = agent(1);
        let ctx = TestCtx::new(7, &[owner]);
        let id = store_id(9);
        let group = vec![7u8; 16];
        let mut target =
            KvStore::new_group_signed(id, "Wiki".to_string(), owner, group.clone(), ctx.clone())
                .expect("target");
        target
            .put(
                "local".to_string(),
                b"keep".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("local");
        let mut hostile = KvStore::new_group_signed(id, "Renamed".to_string(), owner, group, ctx)
            .expect("hostile");
        hostile
            .put(
                "remote".to_string(),
                b"inject".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("remote");
        hostile.allowed_writers.insert(agent(9));

        assert!(target.merge(&hostile).is_err());
        assert!(target.get("local").is_some());
        assert!(target.get("remote").is_none());
        assert_eq!(target.name(), "Wiki");
        assert!(!target.allowed_writers.contains(&agent(9)));
    }

    #[test]
    fn group_signed_retained_image_rejects_invalid_entries_atomically() {
        let owner = agent(1);
        let ctx = TestCtx::new(7, &[owner]);
        let id = store_id(10);
        let group = vec![7u8; 16];
        let mut target =
            KvStore::new_group_signed(id, "Wiki".to_string(), owner, group.clone(), ctx.clone())
                .expect("target");
        target
            .put(
                "local".to_string(),
                b"keep".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("local");
        let before = bincode::serialize(&target).expect("snapshot target");

        let mut hostile =
            KvStore::new_group_signed(id, "Wiki".to_string(), owner, group, ctx).expect("hostile");
        hostile
            .put(
                "valid".to_string(),
                b"new".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("valid");
        hostile
            .put(
                "bad".to_string(),
                b"bad".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("bad");
        hostile
            .entries
            .get_mut("bad")
            .expect("bad entry")
            .content_hash = [0; 32];

        assert!(target
            .merge_group_retained_image(&hostile, owner, peer(1))
            .is_err());
        assert_eq!(
            bincode::serialize(&target).expect("unchanged target"),
            before
        );

        let bad = hostile.entries.get_mut("bad").expect("bad entry");
        bad.content_hash = *blake3::hash(&bad.value).as_bytes();
        bad.key = "wrong-map-key".to_string();
        assert!(target
            .merge_group_retained_image(&hostile, owner, peer(1))
            .is_err());
        assert_eq!(
            bincode::serialize(&target).expect("unchanged target"),
            before
        );

        let bad = hostile.entries.get_mut("bad").expect("bad entry");
        bad.key = "bad".to_string();
        bad.value = vec![0; crate::kv::entry::MAX_INLINE_SIZE + 1];
        bad.content_hash = *blake3::hash(&bad.value).as_bytes();
        assert!(matches!(
            target.merge_group_retained_image(&hostile, owner, peer(1)),
            Err(KvError::ValueTooLarge { .. })
        ));
        assert_eq!(
            bincode::serialize(&target).expect("unchanged target"),
            before
        );
    }

    #[test]
    fn encrypted_with_context_authorizes_active_members() {
        // WHY (#341 Phase B): the ONLY production construction path for the
        // Encrypted policy is new_encrypted with a live secure context, and
        // from that moment the v1 write rule is ACTIVE GROUP MEMBERSHIP at
        // every enforcement point — is_authorized, local writes, and the
        // inbound merge — while non-members are rejected everywhere.
        let owner = agent(1);
        let member = agent(2);
        let outsider = agent(9);
        let group_id = vec![7u8; 16];
        let ctx = TestCtx::new(7, &[owner, member]);

        let mut store = KvStore::new_encrypted(
            store_id(3),
            "GroupStore".to_string(),
            owner,
            group_id.clone(),
            Arc::clone(&ctx) as Arc<dyn KvSecureContext>,
        )
        .expect("encrypted store");
        assert!(store.is_encrypted());
        assert!(store.secure_context().is_some());

        // Membership rule, at every enforcement point.
        assert!(store.is_authorized(&owner));
        assert!(store.is_authorized(&member));
        assert!(!store.is_authorized(&outsider));
        store.authorize_local_write(&member).expect("member writes");
        let err = store
            .authorize_local_write(&outsider)
            .expect_err("outsider must not write");
        assert!(matches!(err, KvError::Unauthorized(_)), "got {err:?}");

        // Inbound merge: a member delta applies; an outsider delta applies
        // nothing (silent reject).
        let mut member_view = KvStore::new_encrypted(
            store_id(3),
            String::new(),
            owner,
            group_id.clone(),
            Arc::clone(&ctx) as Arc<dyn KvSecureContext>,
        )
        .expect("member replica");
        member_view.authorize_local_write(&member).expect("member");
        member_view
            .put(
                "mkey".to_string(),
                b"mv".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("member put");
        let delta = member_view.full_delta().expect("full delta");
        store
            .merge_delta(&delta, peer(2), Some(&member))
            .expect("member merge");
        assert_eq!(
            store.get("mkey").map(|e| e.value.clone()),
            Some(b"mv".to_vec()),
            "member delta applies"
        );

        let mut outsider_view =
            KvStore::new_encrypted_unchecked(store_id(3), String::new(), owner, group_id.clone());
        outsider_view
            .set_secure_context(Arc::clone(&ctx) as Arc<dyn KvSecureContext>)
            .expect("attach ctx");
        let d2 = outsider_view.full_delta().expect("full delta");
        let before = store.current_version();
        store
            .merge_delta(&d2, peer(9), Some(&outsider))
            .expect("outsider merge is a silent reject");
        assert_eq!(
            store.current_version(),
            before,
            "outsider delta must not mutate"
        );

        // Context binding guards: a foreign-group context is refused at
        // construction AND at re-attachment; a non-encrypted store refuses
        // attachment outright.
        let foreign = TestCtx::new(8, &[owner]);
        assert!(KvStore::new_encrypted(
            store_id(4),
            "X".to_string(),
            owner,
            group_id.clone(),
            foreign.clone(),
        )
        .is_err());
        let mut signed_store =
            KvStore::new(store_id(5), "S".to_string(), owner, AccessPolicy::Signed)
                .expect("signed store");
        let err = signed_store
            .set_secure_context(foreign)
            .expect_err("non-encrypted store must refuse a context");
        assert!(
            matches!(err, KvError::EncryptedPolicyReserved { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn encrypted_with_context_adopts_owner_checkpoint() {
        // WHY (#341 Phase B): gate 0 of try_adopt_full_snapshot must reject
        // ONLY context-less Encrypted replicas (Phase A state). With a live
        // context the sealed path has already authenticated authorship, so
        // the ordinary gates (anchor, signature, binding, root) apply and a
        // late joiner cold-recovers the group store exactly like Signed.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let member = agent(2);
        let group_id = vec![7u8; 16];
        let ctx = TestCtx::new(7, &[owner, member]);
        let topic = "store/enc-adopt-b";
        let id = KvStoreId::for_topic_owner(topic, &owner);

        let mut owner_store = KvStore::new_encrypted(
            id,
            "S".to_string(),
            owner,
            group_id.clone(),
            Arc::clone(&ctx) as Arc<dyn KvSecureContext>,
        )
        .expect("encrypted owner store");
        owner_store
            .put(
                "k".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let cp = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut delta = owner_store.full_delta().expect("full delta");
        delta.owner_checkpoint = Some(cp);

        // Fresh member replica: empty, anchored on the group creator, opened
        // under the store's name as `lib.rs` opens a member's group store
        // (a stamped empty name would win the name LWW, and the local root
        // would then not match the checkpoint, so it would not be cached).
        let mut joiner = KvStore::new_encrypted(
            id,
            "S".to_string(),
            owner,
            group_id,
            Arc::clone(&ctx) as Arc<dyn KvSecureContext>,
        )
        .expect("encrypted joiner");
        joiner
            .merge_delta(&delta, peer(9), Some(&owner))
            .expect("merge");
        assert_eq!(
            joiner.get("k").map(|e| e.value.clone()),
            Some(b"v".to_vec()),
            "owner checkpoint adopts on a context-ful encrypted replica"
        );
        assert_eq!(joiner.highest_checkpoint_seq, 1, "high-water advances");
        assert!(joiner.latest_checkpoint.is_some(), "checkpoint cached");
        assert!(
            matches!(joiner.policy(), AccessPolicy::Encrypted { .. }),
            "policy stays Encrypted"
        );
    }

    #[test]
    fn encrypted_policy_is_terminal() {
        // WHY (#341 Phase B): members joined on the confidentiality promise,
        // so no owner-signed announce or checkpoint may silently un-encrypt
        // a replica (that would move it back onto plaintext paths). The
        // same-group refresh IS allowed; any other transition — including a
        // different group binding — is rejected.
        let owner = agent(1);
        let group_id = vec![7u8; 16];
        let ctx = TestCtx::new(7, &[owner]);
        let mut store = KvStore::new_encrypted(
            store_id(8),
            "T".to_string(),
            owner,
            group_id.clone(),
            Arc::clone(&ctx) as Arc<dyn KvSecureContext>,
        )
        .expect("encrypted store");

        // Owner-signed downgrade announce: rejected, policy unchanged.
        let err = store
            .learn_ownership(owner, AccessPolicy::Signed, 5, &owner)
            .expect_err("downgrade announce must be rejected");
        assert!(
            matches!(err, KvError::OwnerTokenInvalid(ref m) if m.contains("encrypted policy is terminal")),
            "got {err:?}"
        );
        let err = store
            .learn_ownership(
                owner,
                AccessPolicy::Encrypted {
                    group_id: vec![9; 16],
                },
                5,
                &owner,
            )
            .expect_err("re-binding announce must be rejected");
        assert!(matches!(err, KvError::OwnerTokenInvalid(_)), "got {err:?}");

        // Same-group refresh at a forward version: allowed.
        store
            .learn_ownership(
                owner,
                AccessPolicy::Encrypted {
                    group_id: group_id.clone(),
                },
                5,
                &owner,
            )
            .expect("same-group refresh applies");
        assert!(store.is_encrypted());

        // A checkpoint claiming Signed must not ADOPT (gate 6c). Built so
        // the checkpoint signer IS the anchored owner — every other gate
        // (anchor, signature, binding, root) passes, and adoption is
        // rejected solely by the terminal-encrypted rule. The content may
        // still flow through the membership-gated sender-auth path, and the
        // relay cache may carry the checkpoint, but the replica's POLICY
        // never leaves Encrypted.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let ctx = TestCtx::new(7, &[owner]);
        let topic = "store/enc-terminal";
        let id = KvStoreId::for_topic_owner(topic, &owner);
        let mut signed_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed).expect("signed store");
        signed_store
            .put(
                "k".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let cp = checkpoint_for(&signed_store, topic, &kp, 1);
        assert!(matches!(cp.policy, AccessPolicy::Signed));
        let mut delta = signed_store.full_delta().expect("full delta");
        delta.owner_checkpoint = Some(cp);

        let mut encrypted_replica = KvStore::new_encrypted(
            id,
            String::new(),
            owner,
            group_id,
            Arc::clone(&ctx) as Arc<dyn KvSecureContext>,
        )
        .expect("encrypted replica");
        encrypted_replica
            .merge_delta(&delta, peer(9), Some(&owner))
            .expect("merge");
        assert!(
            encrypted_replica.is_encrypted(),
            "policy must stay Encrypted after a Signed-claiming checkpoint"
        );
        assert_eq!(
            encrypted_replica.highest_checkpoint_seq, 0,
            "Signed-claiming checkpoint must not be adopted (no high-water advance)"
        );
        assert!(
            encrypted_replica.latest_checkpoint.is_none(),
            "Signed-claiming checkpoint must not be cached or adopted"
        );
    }

    #[test]
    fn reserved_encrypted_rejects_unkeyed_authorize_write() {
        // WHY (#341 Phase A follow-up): authorize_write was unconditionally
        // permissive on the reserved Encrypted policy, so the handle layer's
        // remove path (check_local_remove -> authorize_write) could mutate a
        // context-less Encrypted replica. It must now be fail-closed without
        // a context (and membership-gated with one).
        let owner = agent(1);
        let group_id = vec![7u8; 16];
        let ctx = TestCtx::new(7, &[owner]);

        let mut reserved =
            KvStore::new_encrypted_unchecked(store_id(6), "R".to_string(), owner, group_id.clone());
        let err = reserved
            .authorize_write(&owner, "k")
            .expect_err("context-less authorize_write must fail closed");
        assert!(
            matches!(err, KvError::EncryptedPolicyReserved { .. }),
            "got {err:?}"
        );

        reserved
            .set_secure_context(Arc::clone(&ctx) as Arc<dyn KvSecureContext>)
            .expect("attach");
        reserved
            .authorize_write(&owner, "k")
            .expect("active member passes");
    }

    // -- Owner-signed checkpoint protocol (cold-recovery while owner offline) --

    /// Build an owner-signed checkpoint for a store's current content.
    fn checkpoint_for(
        store: &KvStore,
        topic: &str,
        kp: &crate::identity::AgentKeypair,
        seq: u64,
    ) -> OwnerCheckpoint {
        let pairs = store.checkpoint_pairs();
        let root = content_root(store.id(), store.name(), &pairs);
        make_owner_checkpoint(OwnerCheckpointParams {
            topic,
            store_id: store.id(),
            secret_key: kp.secret_key(),
            public_key: kp.public_key(),
            policy: store.policy(),
            policy_version: store.policy_version(),
            checkpoint_seq: seq,
            content_root: root,
            timestamp: 0,
        })
        .expect("sign checkpoint")
    }

    #[test]
    fn cold_join_from_replica_with_owner_offline() {
        // Owner writes + checkpoints, then is offline. A non-owner replica
        // relays full_delta + checkpoint. An anchored joiner verifies the
        // owner signature + content root and adopts — independent of relayer.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let relayer = agent(9);
        let topic = "store/cold";
        let id = KvStoreId::for_topic_owner(topic, &owner);

        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        owner_store
            .put(
                "k".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let cp = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut delta = owner_store.full_delta().expect("full delta");
        delta.owner_checkpoint = Some(cp.clone());

        // Anchored joiner; the relayer is NOT the owner.
        let mut joiner =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        joiner
            .merge_delta(&delta, peer(9), Some(&relayer))
            .expect("checkpoint-gated merge");
        assert!(joiner.get("k").is_some(), "adopted relayed owner content");
        assert_eq!(joiner.highest_checkpoint_seq, 1);
    }

    #[test]
    fn adoption_does_not_cache_a_checkpoint_the_merge_no_longer_matches() {
        // WHY (#1987 review): adoption MERGES the signed entries, so a local
        // entry later than the signed one wins. The replica must then not
        // cache (and later relay) the checkpoint: its root no longer matches
        // the replica's entries.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/adopt-merge";
        let id = KvStoreId::for_topic_owner(topic, &owner);
        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        owner_store
            .put(
                "k".to_string(),
                b"signed".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let cp1 = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut first = owner_store.full_delta().expect("full delta");
        first.owner_checkpoint = Some(cp1);
        let mut replica =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        replica
            .merge_delta(&first, peer(9), Some(&agent(9)))
            .expect("adopt checkpoint 1");
        assert!(replica.latest_checkpoint.is_some(), "matching: cached");

        // The replica now holds a later value under `k`.
        let local = replica.entries_mut_for_test().get_mut("k").expect("k");
        local.value = b"later".to_vec();
        local.content_hash = *blake3::hash(b"later").as_bytes();
        local.updated_at = local.updated_at.saturating_add(1_000);

        // Checkpoint 2 signs `k` unchanged plus a new key.
        owner_store
            .put(
                "k2".to_string(),
                b"two".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put k2");
        let cp2 = checkpoint_for(&owner_store, topic, &kp, 2);
        let mut second = owner_store.full_delta().expect("full delta");
        second.owner_checkpoint = Some(cp2);
        replica
            .merge_delta(&second, peer(9), Some(&agent(9)))
            .expect("adopt checkpoint 2");

        assert_eq!(
            replica.get("k").map(|e| e.value.clone()),
            Some(b"later".to_vec()),
            "the later local entry wins the merge"
        );
        assert!(replica.get("k2").is_some(), "the new signed key is adopted");
        assert_eq!(replica.highest_checkpoint_seq, 2, "high-water advances");
        assert!(
            replica.latest_checkpoint.is_none(),
            "a checkpoint that no longer matches the entries is not cached"
        );
        assert!(
            replica
                .full_delta()
                .expect("full delta")
                .owner_checkpoint
                .is_none(),
            "and it is never relayed"
        );
    }

    #[test]
    fn full_replace_ignores_relay_injected_removed() {
        // A non-owner relay copies the owner's valid full-snapshot checkpoint of
        // {k} and injects removed={k}. The full-replace adopt path IGNORES the
        // untrusted `delta.removed` — the owner-signed set {k} is authoritative —
        // so the injection cannot truncate the joiner's recovered state.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/inject";
        let id = KvStoreId::for_topic_owner(topic, &owner);
        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        owner_store
            .put(
                "k".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let cp = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut delta = owner_store.full_delta().expect("full delta");
        delta.owner_checkpoint = Some(cp);
        let mut tags = std::collections::HashSet::new();
        tags.insert((peer(9), 1));
        delta.removed.insert("k".to_string(), tags);

        let mut joiner =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        joiner
            .merge_delta(&delta, peer(9), Some(&agent(9)))
            .expect("merge");
        assert!(
            joiner.get("k").is_some(),
            "injected removed must not truncate the owner-signed set"
        );
        assert_eq!(joiner.highest_checkpoint_seq, 1, "checkpoint adopted");
    }

    #[test]
    fn stale_owner_delta_below_adopted_checkpoint_cannot_resurrect_deleted_keys() {
        // v0.31.1 retest defect: owner writes k1 (checkpoint 1), later
        // deletes it and writes k_final (checkpoint 2). A fresh anchored
        // joiner cold-recovers checkpoint 2 ({k_final} only) from a relay,
        // then the gossip replay/cache window re-delivers the owner's OLD
        // k1 delta (still genuinely owner-signed, checkpoint 1 attached).
        // The joiner holds no OR-Set tombstone for k1 — it never observed
        // that add — so without the stale-delta gate the sender-auth path
        // re-adds it, resurrecting an owner-deleted key.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/resurrect";
        let id = KvStoreId::for_topic_owner(topic, &owner);

        // Owner at time 1: state {k1}; the broadcast delta carries cp seq 1.
        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        owner_store
            .put(
                "k1".to_string(),
                b"alpha".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put k1");
        let cp1 = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut stale_delta = owner_store.full_delta().expect("full delta");
        stale_delta.owner_checkpoint = Some(cp1);

        // Owner at time 2: k1 deleted, k_final written; checkpoint seq 2.
        owner_store.remove("k1").expect("remove k1");
        owner_store
            .put(
                "k_final".to_string(),
                b"final".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put k_final");
        let cp2 = checkpoint_for(&owner_store, topic, &kp, 2);
        let mut snapshot = owner_store.full_delta().expect("full delta");
        snapshot.owner_checkpoint = Some(cp2);

        // Fresh anchored joiner cold-recovers checkpoint 2 via a relay.
        let mut joiner =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        joiner
            .merge_delta(&snapshot, peer(9), Some(&agent(9)))
            .expect("adopt checkpoint 2");
        assert!(joiner.get("k_final").is_some(), "recovered final state");
        assert!(joiner.get("k1").is_none(), "k1 deleted in checkpoint 2");
        assert_eq!(joiner.highest_checkpoint_seq, 2);

        // Replay the stale owner delta (writer == owner, so the sender-auth
        // path WOULD authorize it). The stale-delta gate must drop it.
        joiner
            .merge_delta(&stale_delta, peer(1), Some(&owner))
            .expect("stale replay merge");
        assert!(
            joiner.get("k1").is_none(),
            "owner-deleted key must not resurrect from a stale owner-signed delta"
        );
        assert_eq!(joiner.highest_checkpoint_seq, 2, "high-water unchanged");
    }

    #[test]
    fn full_replace_drops_keys_absent_from_newer_checkpoint() {
        // A replica holding {k1,k2} (from a seq-1 checkpoint) adopts a NEWER
        // seq-2 checkpoint whose signed set is {k1} — the owner deleted k2.
        // Full-replace drops k2; it is NOT resurrected. Proves checkpoint
        // adoption is authoritative full-state, not additive (the exact
        // delete-recovery invariant the soak's owner_offline gate exercises).
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/delrec";
        let id = KvStoreId::for_topic_owner(topic, &owner);
        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        owner_store
            .put(
                "k1".to_string(),
                b"a".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put k1");
        owner_store
            .put(
                "k2".to_string(),
                b"b".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put k2");
        let cp1 = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut d1 = owner_store.full_delta().expect("full delta");
        d1.owner_checkpoint = Some(cp1);
        let mut joiner =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        joiner
            .merge_delta(&d1, peer(9), Some(&agent(9)))
            .expect("adopt cp1");
        assert!(
            joiner.get("k1").is_some() && joiner.get("k2").is_some(),
            "joiner recovered both keys from cp1"
        );

        // Owner deletes k2 and cuts a newer checkpoint over {k1}.
        owner_store.remove("k2").expect("delete k2");
        let cp2 = checkpoint_for(&owner_store, topic, &kp, 2);
        let mut d2 = owner_store.full_delta().expect("full delta");
        d2.owner_checkpoint = Some(cp2);
        joiner
            .merge_delta(&d2, peer(9), Some(&agent(9)))
            .expect("adopt cp2");
        assert!(joiner.get("k1").is_some(), "k1 survives");
        assert!(
            joiner.get("k2").is_none(),
            "k2 dropped by full-replace, not resurrected"
        );
        assert_eq!(joiner.highest_checkpoint_seq, 2);
    }

    #[test]
    fn relay_tamper_rejected() {
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/tamper";
        let id = KvStoreId::for_topic_owner(topic, &owner);
        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        owner_store
            .put(
                "k".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let cp = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut delta = owner_store.full_delta().expect("full delta");
        // Tamper: mutate value AND recompute content_hash (an honest re-hash).
        // The recomputed content_root no longer matches the checkpoint root.
        if let Some((e, _)) = delta.added.get_mut("k") {
            e.value = b"TAMPERED".to_vec();
            e.content_hash = *blake3::hash(b"TAMPERED").as_bytes();
        }
        delta.owner_checkpoint = Some(cp);
        let mut joiner =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        joiner
            .merge_delta(&delta, peer(9), Some(&agent(9)))
            .expect("no error");
        assert!(
            joiner.get("k").is_none(),
            "tampered relay must not be adopted"
        );
        assert_eq!(joiner.highest_checkpoint_seq, 0);
    }

    #[test]
    fn checkpoint_replay_downgrade_rejected() {
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/replay";
        let id = KvStoreId::for_topic_owner(topic, &owner);
        let owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        let cp_old = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut joiner =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        joiner.highest_checkpoint_seq = 5; // already adopted a newer checkpoint
        let mut delta = KvStoreDelta::new(0);
        delta.owner_checkpoint = Some(cp_old);
        joiner
            .merge_delta(&delta, peer(9), Some(&agent(9)))
            .expect("no error");
        assert_eq!(joiner.highest_checkpoint_seq, 5, "stale replay dropped");
    }

    #[test]
    fn unanchored_joiner_rejects_checkpoint() {
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/unanchored";
        let id = KvStoreId::for_topic_owner(topic, &owner);
        let owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        let cp = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut delta = KvStoreDelta::new(0);
        delta.owner_checkpoint = Some(cp);
        // No-anchor replica: must never learn the owner from a relay.
        let mut joiner = KvStore::new_replica(id, String::new(), None, AnchorChannel::Persistence);
        joiner
            .merge_delta(&delta, peer(9), Some(&agent(9)))
            .expect("no error");
        assert!(
            joiner.owner().is_none(),
            "owner never learned from checkpoint"
        );
        assert!(joiner.get("k").is_none());
    }

    #[test]
    fn cross_store_checkpoint_replay_rejected() {
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic_a = "store/A";
        let id_a = KvStoreId::for_topic_owner(topic_a, &owner);
        let owner_store =
            KvStore::new(id_a, "A".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        let cp = checkpoint_for(&owner_store, topic_a, &kp, 1);
        // Replay onto a different store B (different topic -> different id).
        let id_b = KvStoreId::for_topic_owner("store/B", &owner);
        let mut delta = KvStoreDelta::new(0);
        delta.owner_checkpoint = Some(cp);
        let mut joiner_b =
            KvStore::new_replica(id_b, String::new(), Some(owner), AnchorChannel::RestParam);
        joiner_b
            .merge_delta(&delta, peer(9), Some(&agent(9)))
            .expect("no error");
        assert_eq!(
            joiner_b.highest_checkpoint_seq, 0,
            "cross-store replay rejected"
        );
    }

    #[test]
    fn checkpoint_verify_rejects_forged_owner() {
        // A checkpoint signed by a rogue key claiming a different owner must
        // fail verification (owner binding + signature).
        let owner = agent(1);
        let rogue_kp = crate::identity::AgentKeypair::generate().expect("rogue keypair");
        let topic = "store/forged";
        let id = KvStoreId::for_topic_owner(topic, &owner);
        // Rogue signs a checkpoint whose owner_pubkey is the ROGUE's key.
        let cp = make_owner_checkpoint(OwnerCheckpointParams {
            topic,
            store_id: &id,
            secret_key: rogue_kp.secret_key(),
            public_key: rogue_kp.public_key(),
            policy: &AccessPolicy::Signed,
            policy_version: 0,
            checkpoint_seq: 1,
            content_root: [0u8; 32],
            timestamp: 0,
        })
        .expect("sign");
        // Verify against the REAL owner -> must fail (rogue pubkey != owner).
        let err = cp.verify(&owner).expect_err("forged checkpoint rejected");
        assert!(matches!(err, KvError::OwnerTokenInvalid(_)));
    }

    #[test]
    fn owner_returns_advances_high_water_mark() {
        // After a relay-adopt at seq N, a live owner delta (sender-auth) at a
        // higher checkpoint seq merges and advances the high-water mark. No
        // conflict between relay-adopt and live owner writes.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/return";
        let id = KvStoreId::for_topic_owner(topic, &owner);
        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        owner_store
            .put(
                "k".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let cp1 = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut relay = owner_store.full_delta().expect("full delta");
        relay.owner_checkpoint = Some(cp1);
        // Joiner adopts the relay at seq 1.
        let mut joiner =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        joiner
            .merge_delta(&relay, peer(9), Some(&agent(9)))
            .expect("relay adopt");
        assert_eq!(joiner.highest_checkpoint_seq, 1);
        // Owner writes a new key, then republishes its FULL state with a
        // forward checkpoint at seq 2. The joiner re-verifies the owner sig +
        // content root and adopts, advancing the high-water mark. (An
        // incremental live delta would merge via sender-auth but not advance
        // the mark, since the mark reflects root-verified full state.)
        owner_store
            .put(
                "k2".to_string(),
                b"v2".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let cp2 = checkpoint_for(&owner_store, topic, &kp, 2);
        let mut full2 = owner_store.full_delta().expect("full delta");
        full2.owner_checkpoint = Some(cp2);
        joiner
            .merge_delta(&full2, peer(9), Some(&agent(9)))
            .expect("full relay adopt");
        assert!(joiner.get("k2").is_some());
        assert_eq!(joiner.highest_checkpoint_seq, 2);
    }
    // ====================================================================
    // P0/P1 regression suite — owner-checkpoint relay integrity, full-state
    // reconciliation, and durable high-water mark.
    //
    // These target the FIXED contract (v2 content_root binding every adopted
    // field; content_hash==blake3(value) & outer_key==inner_key enforced
    // before any mutation; incremental vs full-snapshot reconciliation;
    // persisted checkpoint epoch). Each fails on the pre-fix tree and passes
    // only with the complete commitment + full-snapshot reconciliation.
    // ====================================================================

    /// Deterministic (key, value, content_hash) view of a store's active state,
    /// sorted by key, so two stores can be compared for EXACT equality
    /// independent of HashMap iteration order.
    fn snapshot(s: &KvStore) -> Vec<(String, Vec<u8>, [u8; 32])> {
        let active = s.active_entries();
        let mut v: Vec<_> = active
            .iter()
            .map(|e| (e.key.clone(), e.value.clone(), e.content_hash))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Mirror of `Daemon::put_with_delta` + `produce_checkpoint`: perform an
    /// owner local write, then build the incremental put-delta carrying an
    /// owner-signed full-state checkpoint at the next sequence — exactly what
    /// the live sync path publishes.
    #[allow(clippy::too_many_arguments)]
    fn owner_put_delta(
        owner: &mut KvStore,
        key: &str,
        value: &[u8],
        content_type: &str,
        topic: &str,
        kp: &crate::identity::AgentKeypair,
        seq: u64,
        p: PeerId,
    ) -> KvStoreDelta {
        owner
            .put(key.to_string(), value.to_vec(), content_type.to_string(), p)
            .expect("owner put");
        let entry = owner.get(key).cloned().expect("entry readable after put");
        let version = owner.current_version();
        let mut delta = KvStoreDelta::for_put(
            key.to_string(),
            entry,
            (p, owner.next_seq().expect("sequence")),
            version,
        );
        delta.owner_checkpoint = Some(checkpoint_for(owner, topic, kp, seq));
        // Attach the owner's authoritative name so a fresh replica (name="")
        // learns it from the incremental delta before maybe_cache_checkpoint
        // recomputes the root — mirrors the lib.rs put_with_delta fix.
        delta.name_update = Some(owner.name_register().clone());
        delta
    }

    /// Mirror of `Daemon::remove_with_delta` + `produce_checkpoint`: remove a
    /// key and build the incremental remove-delta carrying an owner-signed
    /// full-state checkpoint at the next sequence.
    fn owner_remove_delta(
        owner: &mut KvStore,
        key: &str,
        topic: &str,
        kp: &crate::identity::AgentKeypair,
        seq: u64,
    ) -> KvStoreDelta {
        owner.remove(key).expect("owner remove");
        let mut d = KvStoreDelta::new(owner.current_version());
        d.removed
            .insert(key.to_string(), std::collections::HashSet::new());
        d.owner_checkpoint = Some(checkpoint_for(owner, topic, kp, seq));
        // Attach the owner's authoritative name (mirrors remove_with_delta).
        d.name_update = Some(owner.name_register().clone());
        d
    }

    #[test]
    fn relay_forgery_per_field_tamper_rejected() {
        // P0: a non-owner relay copies a valid full-snapshot checkpoint and
        // mutates a SINGLE field the old content_root did not bind. The v2
        // commitment (outer+inner key, value, content_hash, content_type,
        // metadata, timestamps, name) plus the independent
        // content_hash==blake3(value) / outer_key==inner_key checks must reject
        // every variant WITHOUT mutating entries, policy, the checkpoint cache,
        // or the high-water mark. The OR-Set `UniqueTag` is deliberately NOT
        // bound (it is add/remove bookkeeping, not content provenance, and
        // removals work by key), so a tag-only tamper is out of scope here.
        //
        // The pre-existing `relay_tamper_rejected` test mutated value AND
        // recomputed content_hash (an honest re-hash); it therefore never
        // exercised the actual exploit — swapping value while LEAVING
        // content_hash untouched. This closes that gap and binds the rest.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/forgery";
        let id = KvStoreId::for_topic_owner(topic, &owner);

        let mut owner_store =
            KvStore::new(id, "Legit".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        owner_store
            .put(
                "k".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner put");
        let cp = checkpoint_for(&owner_store, topic, &kp, 1);

        // Legit control: an un-tampered non-owner relay IS adopted. This proves
        // every rejection below is tamper detection, not the relayer identity.
        {
            let mut legit = owner_store.full_delta().expect("full delta");
            legit.owner_checkpoint = Some(cp.clone());
            let mut j =
                KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
            j.merge_delta(&legit, peer(9), Some(&agent(9)))
                .expect("legit adopt");
            assert!(j.get("k").is_some(), "legit relay must adopt");
            assert_eq!(j.highest_checkpoint_seq, 1);
        }

        #[allow(clippy::type_complexity)]
        let mutators: Vec<(&str, Box<dyn FnOnce(&mut KvStoreDelta)>)> = vec![
            // The real exploit: swap value, KEEP content_hash unchanged.
            (
                "value_swap_unchanged_hash",
                Box::new(|d| {
                    d.added.get_mut("k").unwrap().0.value = b"PWNED".to_vec();
                }),
            ),
            (
                "content_type",
                Box::new(|d| {
                    d.added.get_mut("k").unwrap().0.content_type = "evil/x".to_string();
                }),
            ),
            (
                "metadata",
                Box::new(|d| {
                    d.added
                        .get_mut("k")
                        .unwrap()
                        .0
                        .metadata
                        .insert("injected".to_string(), "yes".to_string());
                }),
            ),
            (
                "created_at",
                Box::new(|d| {
                    d.added.get_mut("k").unwrap().0.created_at = 0;
                }),
            ),
            (
                "updated_at",
                Box::new(|d| {
                    d.added.get_mut("k").unwrap().0.updated_at = 0;
                }),
            ),
            (
                "outer_key",
                Box::new(|d| {
                    let pair = d.added.remove("k").unwrap();
                    d.added.insert("k2".to_string(), pair);
                }),
            ),
            (
                "inner_key",
                Box::new(|d| {
                    d.added.get_mut("k").unwrap().0.key = "k2".to_string();
                }),
            ),
            // OR-Set `UniqueTag` is intentionally NOT a case here: it is not
            // bound by the checkpoint (removals work by key, not tag), so a
            // tag-only tamper cannot forge owner-attributed content.
            (
                "store_name",
                Box::new(|d| {
                    d.name_update
                        .as_mut()
                        .unwrap()
                        .set("EVIL".to_string(), peer(9));
                }),
            ),
        ];

        for (name, mutate) in mutators {
            let mut delta = owner_store.full_delta().expect("full delta");
            delta.owner_checkpoint = Some(cp.clone());
            mutate(&mut delta);

            let mut joiner =
                KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
            joiner
                .merge_delta(&delta, peer(9), Some(&agent(9)))
                .expect("silent rejection never errors");

            assert!(
                joiner.get("k").is_none(),
                "{name}: forged entry not adopted"
            );
            assert!(
                joiner.get("k2").is_none(),
                "{name}: forged outer-key entry not adopted"
            );
            assert!(joiner.entries.is_empty(), "{name}: entries untouched");
            assert_eq!(
                *joiner.policy(),
                AccessPolicy::Signed,
                "{name}: policy unchanged"
            );
            assert!(
                joiner.latest_checkpoint.is_none(),
                "{name}: checkpoint cache empty"
            );
            assert_eq!(
                joiner.highest_checkpoint_seq, 0,
                "{name}: high-water mark unchanged"
            );
            assert_ne!(joiner.name(), "EVIL", "{name}: store name not forged");
        }
    }

    #[test]
    fn relay_matches_owner_through_put_update_delete_sequence() {
        // P0: checkpoint recovery must not break after normal multi-write /
        // update / delete use. The relay receives the owner's published
        // incremental deltas (each carrying an owner-signed full-state
        // checkpoint) and must (a) match the owner's exact state after every
        // step and (b) cache each checkpoint via maybe_cache_checkpoint.
        // Pre-fix, an incremental put-delta carried a full-state root that did
        // not match its single-entry set, so the checkpoint was never cached
        // and a delete-to-empty short-circuited without applying `removed`.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/relay-exact";
        let id = KvStoreId::for_topic_owner(topic, &owner);
        let p = peer(1);

        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        let mut relay =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);

        let d1 = owner_put_delta(
            &mut owner_store,
            "k1",
            b"v1",
            "text/plain",
            topic,
            &kp,
            1,
            p,
        );
        relay.merge_delta(&d1, p, Some(&owner)).expect("relay k1");
        assert_eq!(snapshot(&owner_store), snapshot(&relay), "after k1");
        assert_eq!(
            relay.highest_checkpoint_seq, 1,
            "seq1 caches on a fresh replica (name propagated via the incremental delta)"
        );
        assert_eq!(
            relay.name(),
            "S",
            "owner's real name propagated to the fresh replica"
        );

        let d2 = owner_put_delta(
            &mut owner_store,
            "k2",
            b"v2",
            "text/plain",
            topic,
            &kp,
            2,
            p,
        );
        relay.merge_delta(&d2, p, Some(&owner)).expect("relay k2");
        assert_eq!(snapshot(&owner_store), snapshot(&relay), "after k2");
        assert_eq!(
            relay.highest_checkpoint_seq, 2,
            "relay cached cp2 after incremental write (maybe_cache_checkpoint)"
        );

        let d3 = owner_put_delta(
            &mut owner_store,
            "k1",
            b"v1b",
            "application/json",
            topic,
            &kp,
            3,
            p,
        );
        relay
            .merge_delta(&d3, p, Some(&owner))
            .expect("relay update k1");
        assert_eq!(snapshot(&owner_store), snapshot(&relay), "after update k1");
        assert_eq!(relay.highest_checkpoint_seq, 3, "relay cached cp3");

        let d4 = owner_remove_delta(&mut owner_store, "k1", topic, &kp, 4);
        relay
            .merge_delta(&d4, p, Some(&owner))
            .expect("relay delete k1");
        assert_eq!(snapshot(&owner_store), snapshot(&relay), "after delete k1");
        assert!(relay.get("k1").is_none());
        assert_eq!(relay.highest_checkpoint_seq, 4, "relay cached cp4");

        // Delete down to empty — the case where the empty resulting root
        // matched the empty relayed set and pre-fix short-circuited without
        // applying `removed`, leaving replicas retaining the deleted key.
        let d5 = owner_remove_delta(&mut owner_store, "k2", topic, &kp, 5);
        relay
            .merge_delta(&d5, p, Some(&owner))
            .expect("relay delete k2");
        assert_eq!(snapshot(&owner_store), snapshot(&relay), "after delete k2");
        assert!(
            relay.get("k2").is_none(),
            "delete-to-empty reconciled on the checkpoint path"
        );
        assert!(
            relay.active_entries().is_empty(),
            "relay is empty, exactly matching the owner"
        );
        assert_eq!(relay.highest_checkpoint_seq, 5, "relay cached cp5");
    }

    #[test]
    fn offline_anchored_joiner_recovers_multikey_state_from_relay() {
        // P0: while the owner is offline, a fresh anchored joiner connected only
        // to a non-owner relay must recover the owner's exact multi-key final
        // state from the relayed owner checkpoint. Pre-fix, the relay never
        // cached the post-second-write checkpoint (it held a stale one-key
        // root), so its full delta's root mismatched the two-key relayed set
        // and the joiner rejected recovery, ending empty.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/offline-recovery";
        let id = KvStoreId::for_topic_owner(topic, &owner);
        let p = peer(1);

        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        let mut relay =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);

        let d1 = owner_put_delta(
            &mut owner_store,
            "k1",
            b"v1",
            "text/plain",
            topic,
            &kp,
            1,
            p,
        );
        relay.merge_delta(&d1, p, Some(&owner)).expect("relay k1");
        let d2 = owner_put_delta(
            &mut owner_store,
            "k2",
            b"v2",
            "text/plain",
            topic,
            &kp,
            2,
            p,
        );
        relay.merge_delta(&d2, p, Some(&owner)).expect("relay k2");
        assert_eq!(
            relay.highest_checkpoint_seq, 2,
            "relay cached the two-key checkpoint"
        );

        // Owner offline: only the relay serves a full delta.
        let relay_full = relay.full_delta().expect("full delta");
        assert!(
            relay_full.owner_checkpoint.is_some(),
            "relay carries a cached owner checkpoint for cold recovery"
        );
        let mut joiner =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        joiner
            .merge_delta(&relay_full, peer(9), Some(&agent(9)))
            .expect("cold-recovery merge");

        assert_eq!(
            snapshot(&joiner),
            snapshot(&owner_store),
            "joiner recovers the exact owner state from the relay"
        );
        assert_eq!(joiner.highest_checkpoint_seq, 2);
    }

    #[test]
    fn checkpoint_high_water_mark_survives_restart_and_rejects_replay() {
        // P0 durability: the checkpoint epoch / high-water mark must be durable.
        // Pre-fix `highest_checkpoint_seq` and `latest_checkpoint` were
        // `#[serde(skip)]`, so a restart reset them to 0 / None; a replayed
        // already-adopted checkpoint was then treated as fresh and re-adopted.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/restart-replay";
        let id = KvStoreId::for_topic_owner(topic, &owner);
        let p = peer(1);

        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        owner_store
            .put("k".to_string(), b"v".to_vec(), "text/plain".to_string(), p)
            .expect("owner put");
        let cp1 = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut snap1 = owner_store.full_delta().expect("full delta");
        snap1.owner_checkpoint = Some(cp1);

        let mut replica =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        replica
            .merge_delta(&snap1, peer(9), Some(&agent(9)))
            .expect("adopt full snapshot");
        assert_eq!(replica.highest_checkpoint_seq, 1);
        assert!(replica.latest_checkpoint.is_some());
        assert!(replica.get("k").is_some());

        // Restart modeled as a durable bincode reload.
        let bytes = bincode::serialize(&replica).expect("serialize");
        let mut restarted: KvStore = bincode::deserialize(&bytes).expect("deserialize");

        assert_eq!(
            restarted.highest_checkpoint_seq, 1,
            "highest_checkpoint_seq persisted across restart (no longer serde(skip))"
        );
        assert!(
            restarted.latest_checkpoint.is_some(),
            "latest_checkpoint persisted across restart"
        );

        // Replay the exact same full snapshot (seq 1): must be a stale no-op.
        let v_before = restarted.current_version();
        restarted
            .merge_delta(&snap1, peer(9), Some(&agent(9)))
            .expect("no error");
        assert_eq!(
            restarted.current_version(),
            v_before,
            "replay of already-adopted checkpoint must not mutate after restart"
        );
        assert_eq!(restarted.highest_checkpoint_seq, 1);

        // A monotonically newer owner checkpoint still advances the mark.
        owner_store
            .put(
                "k2".to_string(),
                b"v2".to_vec(),
                "text/plain".to_string(),
                p,
            )
            .expect("owner put k2");
        let cp2 = checkpoint_for(&owner_store, topic, &kp, 2);
        let mut snap2 = owner_store.full_delta().expect("full delta");
        snap2.owner_checkpoint = Some(cp2);
        restarted
            .merge_delta(&snap2, peer(9), Some(&agent(9)))
            .expect("adopt newer");
        assert_eq!(
            restarted.highest_checkpoint_seq, 2,
            "newer checkpoint advances"
        );
        assert!(restarted.get("k2").is_some());
    }

    // ── AppendOnly policy ───────────────────────────────────────────────
    //
    // WHY these tests exist: AppendOnly makes an owner-signed store
    // tamper-evident against its OWN author. Every path an owner (or anyone)
    // could use to rewrite or truncate history — local put/remove, remote
    // deltas, owner-signed checkpoint adoption — must refuse to touch an
    // existing key. If any of these tests can pass while an existing key's
    // bytes change or disappear, the policy's entire guarantee is void.

    fn append_only_owner_store(owner: AgentId) -> KvStore {
        let mut store = KvStore::new(
            store_id(7),
            "log".to_string(),
            owner,
            AccessPolicy::AppendOnly,
        )
        .expect("kv store");
        store
            .put(
                "k1".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("initial append");
        store
    }

    #[test]
    fn append_only_put_existing_key_different_content_rejected() {
        let owner = agent(1);
        let mut store = append_only_owner_store(owner);
        let err = store
            .put(
                "k1".to_string(),
                b"REWRITTEN".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect_err("owner must not be able to rewrite an existing key");
        assert!(matches!(err, KvError::ImmutableKey(ref k) if k == "k1"));
        assert_eq!(
            store.get("k1").map(|e| e.value.clone()),
            Some(b"v1".to_vec()),
            "original bytes retained"
        );
    }

    #[test]
    fn append_only_put_identical_content_is_idempotent_noop() {
        let owner = agent(1);
        let mut store = append_only_owner_store(owner);
        let v_before = store.current_version();
        store
            .put(
                "k1".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("byte-identical re-put is accepted (retry-friendly)");
        assert_eq!(
            store.current_version(),
            v_before,
            "idempotent re-put is a no-op: no version bump, no state change"
        );
        // Same bytes but a different content type is a mutation — rejected.
        let err = store
            .put(
                "k1".to_string(),
                b"v1".to_vec(),
                "application/json".to_string(),
                peer(1),
            )
            .expect_err("content-type change on an existing key is a mutation");
        assert!(matches!(err, KvError::ImmutableKey(_)));
    }

    #[test]
    fn append_only_remove_rejected() {
        let owner = agent(1);
        let mut store = append_only_owner_store(owner);
        let err = store
            .remove("k1")
            .expect_err("owner must not be able to delete an existing key");
        assert!(matches!(err, KvError::ImmutableKey(ref k) if k == "k1"));
        assert!(
            store.get("k1").is_some(),
            "key retained after rejected delete"
        );
        // A key that never existed still reports KeyNotFound (unchanged).
        assert!(matches!(
            store.remove("ghost"),
            Err(KvError::KeyNotFound(_))
        ));
    }

    #[test]
    fn append_only_owner_delta_rewrite_skipped_value_retained() {
        // A hostile delta authored by the OWNER updating an existing key must
        // be skipped: owner-signed is not exempt from immutability.
        let owner = agent(1);
        let mut store = append_only_owner_store(owner);

        let mut delta = KvStoreDelta::new(99);
        delta.added.insert(
            "k1".to_string(),
            (
                KvEntry::new(
                    "k1".to_string(),
                    b"REWRITTEN".to_vec(),
                    "text/plain".to_string(),
                ),
                (peer(2), 42),
            ),
        );
        // New keys in the same delta must still append fine. (k1 must NOT
        // also appear in `updated` here — the global canonical-map gate
        // drops any delta carrying one key in both maps; that shape has its
        // own tests.)
        delta.added.insert(
            "k2".to_string(),
            (
                KvEntry::new("k2".to_string(), b"v2".to_vec(), "text/plain".to_string()),
                (peer(2), 43),
            ),
        );
        store
            .merge_delta(&delta, peer(2), Some(&owner))
            .expect("violations are skipped, not errors — delta not poisoned");
        assert_eq!(
            store.get("k1").map(|e| e.value.clone()),
            Some(b"v1".to_vec()),
            "existing key retained its original bytes"
        );
        assert_eq!(
            store.get("k2").map(|e| e.value.clone()),
            Some(b"v2".to_vec()),
            "appends in the same delta still apply"
        );

        // The `updated` path is gated identically (separate delta so the
        // canonical-map gate does not trigger).
        let mut delta2 = KvStoreDelta::new(100);
        delta2.updated.insert(
            "k1".to_string(),
            KvEntry::new(
                "k1".to_string(),
                b"REWRITTEN-2".to_vec(),
                "text/plain".to_string(),
            ),
        );
        store
            .merge_delta(&delta2, peer(2), Some(&owner))
            .expect("updated-path violation skipped");
        assert_eq!(
            store.get("k1").map(|e| e.value.clone()),
            Some(b"v1".to_vec()),
            "updated-path rewrite skipped too"
        );
    }

    #[test]
    fn append_only_owner_delta_removal_skipped_key_retained() {
        let owner = agent(1);
        let mut store = append_only_owner_store(owner);

        let mut delta = KvStoreDelta::new(99);
        delta.removed.insert("k1".to_string(), HashSet::new());
        store
            .merge_delta(&delta, peer(2), Some(&owner))
            .expect("removal is skipped, not an error");
        assert!(
            store.get("k1").is_some(),
            "owner-signed removal must not delete an append-only key"
        );
    }

    #[test]
    fn append_only_fresh_joiner_adopts_first_checkpoint() {
        // Cold start: a fresh anchored joiner has no local keys, so the
        // immutability gate is trivially satisfied and adoption proceeds.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/ao-cold";
        let id = KvStoreId::for_topic_owner(topic, &owner);

        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::AppendOnly).expect("kv store");
        owner_store
            .put(
                "k1".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner append");
        let cp = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut snap = owner_store.full_delta().expect("full delta");
        snap.owner_checkpoint = Some(cp);

        let mut joiner =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        joiner
            .merge_delta(&snap, peer(9), Some(&agent(9)))
            .expect("fresh joiner adopts");
        assert_eq!(joiner.highest_checkpoint_seq, 1);
        assert_eq!(
            joiner.get("k1").map(|e| e.value.clone()),
            Some(b"v1".to_vec())
        );
        assert_eq!(
            *joiner.policy(),
            AccessPolicy::AppendOnly,
            "joiner learns the append-only policy from the checkpoint"
        );
    }

    /// Build an owner-signed "rewritten history" snapshot: a fresh store with
    /// the given entries, checkpointed at `seq`. Models an owner forging a
    /// past-state replacement offline.
    fn forged_snapshot(
        id: KvStoreId,
        owner: AgentId,
        kp: &crate::identity::AgentKeypair,
        topic: &str,
        entries: &[(&str, &[u8])],
        seq: u64,
    ) -> KvStoreDelta {
        let mut forged =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::AppendOnly).expect("kv store");
        for (k, v) in entries {
            forged
                .put(
                    (*k).to_string(),
                    v.to_vec(),
                    "text/plain".to_string(),
                    peer(1),
                )
                .expect("forge put");
        }
        let cp = checkpoint_for(&forged, topic, kp, seq);
        let mut snap = forged.full_delta().expect("full delta");
        snap.owner_checkpoint = Some(cp);
        snap
    }

    #[test]
    fn append_only_checkpoint_shrinking_keyset_rejected() {
        // An owner-signed checkpoint that DROPS an existing key must be
        // rejected on a non-fresh replica: local state intact, high-water
        // mark not advanced. An owner truncating its own log is exactly the
        // attack this policy exists to stop.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/ao-shrink";
        let id = KvStoreId::for_topic_owner(topic, &owner);

        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::AppendOnly).expect("kv store");
        for (k, v) in [("k1", b"v1".as_slice()), ("k2", b"v2".as_slice())] {
            owner_store
                .put(k.to_string(), v.to_vec(), "text/plain".to_string(), peer(1))
                .expect("owner append");
        }
        let cp1 = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut snap1 = owner_store.full_delta().expect("full delta");
        snap1.owner_checkpoint = Some(cp1);

        let mut replica =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        replica
            .merge_delta(&snap1, peer(9), Some(&agent(9)))
            .expect("initial adoption");
        assert_eq!(replica.highest_checkpoint_seq, 1);

        // Owner forges history without k2.
        let snap2 = forged_snapshot(id, owner, &kp, topic, &[("k1", b"v1")], 2);
        replica
            .merge_delta(&snap2, peer(9), Some(&owner))
            .expect("rejection is loud in logs but not an error");
        assert!(
            replica.get("k2").is_some(),
            "checkpoint that shrinks the keyset must not delete k2"
        );
        assert_eq!(
            replica.highest_checkpoint_seq, 1,
            "forged checkpoint must not advance the high-water mark"
        );
    }

    #[test]
    fn append_only_checkpoint_rewriting_value_rejected() {
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/ao-rewrite";
        let id = KvStoreId::for_topic_owner(topic, &owner);

        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::AppendOnly).expect("kv store");
        owner_store
            .put(
                "k1".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner append");
        let cp1 = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut snap1 = owner_store.full_delta().expect("full delta");
        snap1.owner_checkpoint = Some(cp1);

        let mut replica =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        replica
            .merge_delta(&snap1, peer(9), Some(&agent(9)))
            .expect("initial adoption");

        // Owner forges history with k1 rewritten (same keyset, new bytes).
        let snap2 = forged_snapshot(id, owner, &kp, topic, &[("k1", b"REWRITTEN")], 2);
        replica
            .merge_delta(&snap2, peer(9), Some(&owner))
            .expect("rejection is loud in logs but not an error");
        assert_eq!(
            replica.get("k1").map(|e| e.value.clone()),
            Some(b"v1".to_vec()),
            "checkpoint rewriting an existing key must not change its bytes"
        );
        assert_eq!(replica.highest_checkpoint_seq, 1);
    }

    #[test]
    fn signed_store_owner_update_and_delete_still_allowed() {
        // Regression guard: AppendOnly enforcement must not leak into Signed
        // stores — the owner's normal update/delete cycle is unchanged.
        let owner = agent(1);
        let mut store = KvStore::new(
            store_id(8),
            "plain".to_string(),
            owner,
            AccessPolicy::Signed,
        )
        .expect("kv store");
        store
            .put(
                "k".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        store
            .put(
                "k".to_string(),
                b"v2".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("Signed store update must still work");
        assert_eq!(
            store.get("k").map(|e| e.value.clone()),
            Some(b"v2".to_vec())
        );
        store
            .remove("k")
            .expect("Signed store delete must still work");
        assert!(store.get("k").is_none());
    }

    // ── AppendOnly hardening (adversarial-review wave) ──────────────────

    #[test]
    fn append_only_downgrade_announce_rejected() {
        // WHY: if an owner-signed announce could flip append_only back to
        // signed, the owner could downgrade, delete freely, and re-upgrade —
        // the policy would be decorative. AppendOnly must be terminal for
        // ANY policy_version (forward or equal).
        let owner = agent(1);
        let mut store = append_only_owner_store(owner);
        let v = store.policy_version();

        // Forward-version downgrade: rejected.
        let err = store
            .learn_ownership(owner, AccessPolicy::Signed, v + 10, &owner)
            .expect_err("forward-version downgrade must be rejected");
        assert!(matches!(err, KvError::OwnerTokenInvalid(_)));
        assert_eq!(*store.policy(), AccessPolicy::AppendOnly);

        // Equal-version downgrade: rejected.
        let err = store
            .learn_ownership(owner, AccessPolicy::Signed, v, &owner)
            .expect_err("equal-version downgrade must be rejected");
        assert!(matches!(err, KvError::OwnerTokenInvalid(_)));
        assert_eq!(*store.policy(), AccessPolicy::AppendOnly);

        // A refresh that KEEPS append_only is still fine.
        store
            .learn_ownership(owner, AccessPolicy::AppendOnly, v + 1, &owner)
            .expect("append_only-preserving refresh is allowed");
        assert_eq!(*store.policy(), AccessPolicy::AppendOnly);
    }

    #[test]
    fn append_only_checkpoint_policy_downgrade_rejected() {
        // WHY: the checkpoint adoption path refreshes policy from cp.policy
        // (step 10). A content-identical checkpoint whose only change is
        // policy=Signed would otherwise downgrade the replica, unfreezing
        // the log. Content equality means the immutability gate alone
        // cannot catch this — the terminal-policy gate must.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/ao-downgrade";
        let id = KvStoreId::for_topic_owner(topic, &owner);

        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::AppendOnly).expect("kv store");
        owner_store
            .put(
                "k1".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner append");
        let cp1 = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut snap1 = owner_store.full_delta().expect("full delta");
        snap1.owner_checkpoint = Some(cp1.clone());

        let mut replica =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        replica
            .merge_delta(&snap1, peer(9), Some(&agent(9)))
            .expect("initial adoption");
        assert_eq!(*replica.policy(), AccessPolicy::AppendOnly);

        // Forge: identical content, policy flipped to Signed, newer seq +
        // newer policy_version.
        let mut forged =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed).expect("kv store");
        forged
            .put(
                "k1".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("forge put");
        let cp2 = checkpoint_for(&forged, topic, &kp, 2);
        let mut snap2 = forged.full_delta().expect("full delta");
        snap2.owner_checkpoint = Some(cp2);

        replica
            .merge_delta(&snap2, peer(9), Some(&owner))
            .expect("rejection is loud in logs but not an error");
        assert_eq!(
            *replica.policy(),
            AccessPolicy::AppendOnly,
            "append_only is terminal: a policy-downgrading checkpoint must not apply"
        );
        assert_eq!(replica.highest_checkpoint_seq, 1);
    }

    #[test]
    fn adoption_rejects_key_in_both_added_and_updated() {
        // WHY: adoption validates one merged view of (added ∪ updated) but
        // applies both maps in sequence — a crafted delta carrying the same
        // key twice with different values could rewrite what was validated.
        // The canonical-map gate must reject the ambiguity outright.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/ao-dup";
        let id = KvStoreId::for_topic_owner(topic, &owner);

        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::AppendOnly).expect("kv store");
        owner_store
            .put(
                "k1".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner append");
        let cp1 = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut snap1 = owner_store.full_delta().expect("full delta");
        snap1.owner_checkpoint = Some(cp1.clone());

        let mut replica =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        replica
            .merge_delta(&snap1, peer(9), Some(&agent(9)))
            .expect("initial adoption");

        // Craft the REAL attack: k1 in `added` with EVIL bytes and a maxed
        // LWW timestamp (so adoption's entry merge would keep it), k1 in
        // `updated` with the benign local entry (so a last-wins validation
        // map sees only the benign copy), and a checkpoint the "owner"
        // signed over the DUPLICATED relayed multiset — which is exactly
        // what step 6's root computation hashes, so without the
        // canonical-map gate the root check passes while adoption ends on
        // the evil bytes.
        let benign = replica.get("k1").expect("local k1").clone();
        let mut evil = KvEntry::new(
            "k1".to_string(),
            b"REWRITTEN".to_vec(),
            "text/plain".to_string(),
        );
        evil.updated_at = u64::MAX;
        let multiset_root = content_root(&id, "S", &[("k1", &evil), ("k1", &benign)]);
        let cp2 = make_owner_checkpoint(OwnerCheckpointParams {
            topic,
            store_id: &id,
            secret_key: kp.secret_key(),
            public_key: kp.public_key(),
            policy: &AccessPolicy::AppendOnly,
            policy_version: 0,
            checkpoint_seq: 2,
            content_root: multiset_root,
            timestamp: 0,
        })
        .expect("sign forged multiset checkpoint");

        let mut dup = KvStoreDelta::new(99);
        dup.added.insert("k1".to_string(), (evil, (peer(2), 42)));
        dup.updated.insert("k1".to_string(), benign);
        dup.name_update = Some(owner_store.name_register().clone());
        dup.owner_checkpoint = Some(cp2);

        replica
            .merge_delta(&dup, peer(9), Some(&owner))
            .expect("rejected adoption falls through safely");
        assert_eq!(
            replica.get("k1").map(|e| e.value.clone()),
            Some(b"v1".to_vec()),
            "duplicate-key delta must not rewrite the validated value"
        );
        assert_eq!(
            replica.highest_checkpoint_seq, 1,
            "forged multiset checkpoint must not advance the high-water mark"
        );
    }

    #[test]
    fn append_only_public_merge_rejected_transactionally() {
        // WHY: KvStore::merge is public API that bypasses every merge_delta
        // gate. It must enforce the same freeze — and atomically, so a
        // violating merge cannot leave partial state behind.
        let owner = agent(1);
        let mut store = append_only_owner_store(owner);
        let v_before = store.current_version();

        // Hostile full-state replica: k1 rewritten (newer LWW timestamp so
        // the entry merge would pick it), plus an innocent new key k9 that
        // must NOT survive the rejected transaction.
        let mut hostile = KvStore::new(
            *store.id(),
            "log".to_string(),
            owner,
            AccessPolicy::AppendOnly,
        )
        .expect("kv store");
        hostile
            .put(
                "k1".to_string(),
                b"REWRITTEN".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("hostile put");
        hostile
            .put(
                "k9".to_string(),
                b"new".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("hostile put");
        if let Some(e) = hostile.entries.get_mut("k1") {
            e.updated_at = u64::MAX; // guarantee LWW would pick the rewrite
        }

        let err = store
            .merge(&hostile)
            .expect_err("public merge must reject an append-only rewrite");
        assert!(matches!(err, KvError::ImmutableKey(_)));
        assert_eq!(
            store.get("k1").map(|e| e.value.clone()),
            Some(b"v1".to_vec()),
            "value retained"
        );
        assert!(
            store.get("k9").is_none(),
            "rejected merge must be transactional — no partial application"
        );
        assert_eq!(store.current_version(), v_before, "no state change at all");

        // A purely-additive merge still works.
        let mut additive = KvStore::new(
            *store.id(),
            "log".to_string(),
            owner,
            AccessPolicy::AppendOnly,
        )
        .expect("kv store");
        additive
            .put(
                "k2".to_string(),
                b"v2".to_vec(),
                "text/plain".to_string(),
                peer(2),
            )
            .expect("additive put");
        store.merge(&additive).expect("additive merge is allowed");
        assert!(store.get("k1").is_some() && store.get("k2").is_some());
    }

    #[test]
    fn append_only_delta_metadata_mutation_with_identical_bytes_skipped() {
        // WHY: entries are frozen in FULL. KvEntry::merge is LWW on
        // updated_at and replaces metadata wholesale — a same-value entry
        // with a newer timestamp could otherwise mutate metadata/updated_at
        // while the bytes "look" unchanged.
        let owner = agent(1);
        let mut store = append_only_owner_store(owner);
        let (meta_before, updated_before) = {
            let e = store.get("k1").expect("k1");
            (e.metadata.clone(), e.updated_at)
        };

        let mut sneaky = KvEntry::new("k1".to_string(), b"v1".to_vec(), "text/plain".to_string());
        sneaky
            .metadata
            .insert("injected".to_string(), "gotcha".to_string());
        sneaky.updated_at = u64::MAX; // LWW would pick this entry

        let mut delta = KvStoreDelta::new(99);
        delta.added.insert("k1".to_string(), (sneaky, (peer(2), 7)));
        store
            .merge_delta(&delta, peer(2), Some(&owner))
            .expect("skipped, not an error");

        let e = store.get("k1").expect("k1 retained");
        assert_eq!(e.metadata, meta_before, "metadata frozen");
        assert_eq!(e.updated_at, updated_before, "updated_at frozen");
    }

    #[test]
    fn two_fresh_joiners_conflicting_snapshots_diverge_detectably() {
        // WHY (documented limitation, P0-D): a fresh joiner has no prior
        // state, so it MUST trust the owner's current signed snapshot —
        // signatures cannot distinguish original history from a rewrite.
        // Two fresh joiners fed different owner-signed snapshots therefore
        // diverge. The detection surface is the adopted checkpoint content
        // root: they differ, and neither replica auto-reconciles (later
        // cross-delivered snapshots hit the immutability gate).
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/ao-fork";
        let id = KvStoreId::for_topic_owner(topic, &owner);

        let snap_x = forged_snapshot(id, owner, &kp, topic, &[("k", b"x")], 1);
        let snap_y = forged_snapshot(id, owner, &kp, topic, &[("k", b"y")], 1);

        let mut a = KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        let mut b = KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        a.merge_delta(&snap_x, peer(9), Some(&agent(9)))
            .expect("A adopts X");
        b.merge_delta(&snap_y, peer(9), Some(&agent(9)))
            .expect("B adopts Y");

        assert_eq!(a.get("k").map(|e| e.value.clone()), Some(b"x".to_vec()));
        assert_eq!(b.get("k").map(|e| e.value.clone()), Some(b"y".to_vec()));
        assert_eq!(a.highest_checkpoint_seq, 1);
        assert_eq!(b.highest_checkpoint_seq, 1);
        let root_a = a.latest_checkpoint.as_ref().expect("A cp").content_root;
        let root_b = b.latest_checkpoint.as_ref().expect("B cp").content_root;
        assert_ne!(
            root_a, root_b,
            "divergence is detectable by comparing adopted checkpoint roots"
        );

        // Cross-feed: A now DROPS the other snapshot (same seq → the
        // stale-delta gate; a newer-seq rewrite would hit the immutability
        // gate instead) — the fork is sticky and visible, never silently
        // reconciled.
        a.merge_delta(&snap_y, peer(9), Some(&owner))
            .expect("skip, not error");
        assert_eq!(
            a.get("k").map(|e| e.value.clone()),
            Some(b"x".to_vec()),
            "A keeps its observed history"
        );
    }

    #[test]
    fn checkpoint_subsumption_is_distinct_from_admission_rejection() {
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/checkpoint-subsumption-outcome";
        let id = KvStoreId::for_topic_owner(topic, &owner);
        let stale = forged_snapshot(id, owner, &kp, topic, &[("deleted", b"old")], 1);
        let current = forged_snapshot(id, owner, &kp, topic, &[("live", b"new")], 2);
        let mut replica =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        assert_eq!(
            replica
                .merge_delta_with_outcome(&current, peer(9), Some(&agent(9)))
                .expect("current checkpoint"),
            MergeOutcome::Applied
        );
        let version = replica.current_version();
        assert_eq!(
            replica
                .merge_delta_with_outcome(&stale, peer(1), Some(&owner))
                .expect("stale checkpoint"),
            MergeOutcome::SubsumedCheckpoint
        );
        assert_eq!(replica.current_version(), version);
        assert!(
            replica.get("deleted").is_none(),
            "stale echo cannot resurrect a key"
        );
        assert!(replica.get("live").is_some());

        let unauthorized = KvStoreDelta::new(0);
        assert_eq!(
            replica
                .merge_delta_with_outcome(&unauthorized, peer(9), Some(&agent(9)))
                .expect("unauthorized merge"),
            MergeOutcome::Rejected(MergeRejection::UnauthorizedWriter)
        );
        let mut ambiguous = KvStoreDelta::new(0);
        let entry = KvEntry::new("ambiguous".into(), b"value".to_vec(), "text/plain".into());
        ambiguous
            .added
            .insert("ambiguous".into(), (entry.clone(), (peer(1), 1)));
        ambiguous.updated.insert("ambiguous".into(), entry);
        assert_eq!(
            replica
                .merge_delta_with_outcome(&ambiguous, peer(1), Some(&owner))
                .expect("ambiguous merge"),
            MergeOutcome::Rejected(MergeRejection::AmbiguousDelta)
        );
        assert!(replica.get("ambiguous").is_none());
    }

    #[test]
    fn rejected_truncated_checkpoint_does_not_poison_later_legit_flow() {
        // WHY: interaction with the PR #230 stale-delta gate. A rejected
        // forged checkpoint must not advance the high-water mark (else it
        // would stale-drop legitimate owner deltas), and a later LEGITIMATE
        // superset checkpoint must still adopt normally, while replays of
        // old snapshots stay stale-dropped.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/ao-truncate";
        let id = KvStoreId::for_topic_owner(topic, &owner);

        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::AppendOnly).expect("kv store");
        for (k, v) in [("k1", b"v1".as_slice()), ("k2", b"v2".as_slice())] {
            owner_store
                .put(k.to_string(), v.to_vec(), "text/plain".to_string(), peer(1))
                .expect("owner append");
        }
        let cp1 = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut snap1 = owner_store.full_delta().expect("full delta");
        snap1.owner_checkpoint = Some(cp1);

        let mut replica =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        replica
            .merge_delta(&snap1, peer(9), Some(&agent(9)))
            .expect("initial adoption");
        assert_eq!(replica.highest_checkpoint_seq, 1);

        // Forged truncation at seq 2: rejected, HWM must NOT move.
        let forged = forged_snapshot(id, owner, &kp, topic, &[("k1", b"v1")], 2);
        replica
            .merge_delta(&forged, peer(9), Some(&owner))
            .expect("skip, not error");
        assert!(replica.get("k2").is_some(), "truncation rejected");
        assert_eq!(
            replica.highest_checkpoint_seq, 1,
            "rejected forge must not advance HWM (would stale-drop legit deltas)"
        );

        // Legit superset at seq 3 still adopts.
        owner_store
            .put(
                "k3".to_string(),
                b"v3".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner append k3");
        let cp3 = checkpoint_for(&owner_store, topic, &kp, 3);
        let mut snap3 = owner_store.full_delta().expect("full delta");
        snap3.owner_checkpoint = Some(cp3);
        replica
            .merge_delta(&snap3, peer(9), Some(&agent(9)))
            .expect("legit superset adopts");
        assert_eq!(replica.highest_checkpoint_seq, 3);
        assert!(replica.get("k3").is_some());

        // Replay of the old seq-1 snapshot: stale-dropped, no mutation.
        let v_before = replica.current_version();
        replica
            .merge_delta(&snap1, peer(9), Some(&agent(9)))
            .expect("stale replay is a no-op");
        assert_eq!(replica.current_version(), v_before);
        assert_eq!(replica.highest_checkpoint_seq, 3);
    }

    #[test]
    fn skip_only_delta_does_not_advance_hwm_or_replace_checkpoint() {
        // WHY: when every mutation in a hostile delta is skipped, the
        // attached (genuine, newer-seq) checkpoint must not be cached either
        // — the post-merge state root does not match it. HWM and
        // latest_checkpoint must be exactly what they were.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/ao-skiponly";
        let id = KvStoreId::for_topic_owner(topic, &owner);

        let mut owner_store =
            KvStore::new(id, "S".to_string(), owner, AccessPolicy::AppendOnly).expect("kv store");
        owner_store
            .put(
                "k1".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner append");
        let cp1 = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut snap1 = owner_store.full_delta().expect("full delta");
        snap1.owner_checkpoint = Some(cp1.clone());

        let mut replica =
            KvStore::new_replica(id, String::new(), Some(owner), AnchorChannel::RestParam);
        replica
            .merge_delta(&snap1, peer(9), Some(&agent(9)))
            .expect("initial adoption");
        let root_before = replica
            .latest_checkpoint
            .as_ref()
            .expect("cp cached")
            .content_root;

        // Hostile: rewrite-only delta with a genuine seq-2 checkpoint over
        // the forged state.
        let hostile = forged_snapshot(id, owner, &kp, topic, &[("k1", b"REWRITTEN")], 2);
        replica
            .merge_delta(&hostile, peer(9), Some(&owner))
            .expect("skip, not error");

        assert_eq!(replica.highest_checkpoint_seq, 1, "HWM unchanged");
        assert_eq!(
            replica
                .latest_checkpoint
                .as_ref()
                .expect("cp still cached")
                .content_root,
            root_before,
            "latest_checkpoint unchanged after a skip-only delta"
        );
    }

    #[test]
    fn append_only_ambiguous_delta_dropped_without_checkpoint() {
        // Standalone global-gate case: no checkpoint attached, so the
        // adoption path is never entered — this exercises merge_delta's own
        // canonical-map gate on an AppendOnly store. Even a NEW key (no
        // immutability conflict at all) carried in both maps drops the
        // whole delta.
        let owner = agent(1);
        let mut store = append_only_owner_store(owner);
        let v_before = store.current_version();

        let mut dup = KvStoreDelta::new(77);
        dup.added.insert(
            "fresh".to_string(),
            (
                KvEntry::new("fresh".to_string(), b"a".to_vec(), "text/plain".to_string()),
                (peer(2), 11),
            ),
        );
        dup.updated.insert(
            "fresh".to_string(),
            KvEntry::new("fresh".to_string(), b"b".to_vec(), "text/plain".to_string()),
        );
        store
            .merge_delta(&dup, peer(2), Some(&owner))
            .expect("dropped, not an error");
        assert!(
            store.get("fresh").is_none(),
            "ambiguous delta dropped whole — neither copy of the new key applies"
        );
        assert_eq!(store.current_version(), v_before, "no state change");
    }

    #[test]
    fn signed_store_ambiguous_added_updated_delta_dropped() {
        // WHY: the canonical-map rule is global, not AppendOnly-only. A delta
        // carrying one key in both `added` and `updated` holds two values for
        // one key in one message — which copy wins would be decided by map
        // iteration/LWW ordering, not by anything the producer expressed. No
        // legitimate producer emits this shape, so merge_delta drops the
        // whole delta for EVERY policy.
        let owner = agent(1);
        let mut store = KvStore::new(
            store_id(9),
            "plain".to_string(),
            owner,
            AccessPolicy::Signed,
        )
        .expect("kv store");
        store
            .put(
                "k".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let v_before = store.current_version();

        let mut dup = KvStoreDelta::new(99);
        dup.added.insert(
            "k".to_string(),
            (
                KvEntry::new("k".to_string(), b"v2".to_vec(), "text/plain".to_string()),
                (peer(2), 7),
            ),
        );
        dup.updated.insert(
            "k".to_string(),
            KvEntry::new("k".to_string(), b"v3".to_vec(), "text/plain".to_string()),
        );
        // An innocent sibling key must not survive either: the ambiguity
        // poisons the whole delta.
        dup.added.insert(
            "other".to_string(),
            (
                KvEntry::new("other".to_string(), b"x".to_vec(), "text/plain".to_string()),
                (peer(2), 8),
            ),
        );

        store
            .merge_delta(&dup, peer(2), Some(&owner))
            .expect("dropped, not an error");
        assert_eq!(
            store.get("k").map(|e| e.value.clone()),
            Some(b"v1".to_vec()),
            "ambiguous delta must not change the key on a Signed store"
        );
        assert!(store.get("other").is_none(), "whole delta dropped");
        assert_eq!(store.current_version(), v_before, "no state change");
    }

    #[test]
    fn access_policy_bincode_discriminants_are_pinned() {
        // WHY: AccessPolicy is bincode-encoded positionally in persisted
        // stores, checkpoints (wire + signing bytes), and deltas. If anyone
        // reorders or inserts a variant mid-enum, every existing store
        // corrupts. This test pins the exact on-wire indices 0..=6.
        let cases: [(AccessPolicy, u32); 7] = [
            (AccessPolicy::Signed, 0),
            (AccessPolicy::Allowlisted, 1),
            (
                AccessPolicy::Encrypted {
                    group_id: Vec::new(),
                },
                2,
            ),
            (AccessPolicy::AppendOnly, 3),
            (AccessPolicy::SelfKeyed, 4),
            (
                AccessPolicy::GroupSigned {
                    group_id: Vec::new(),
                },
                5,
            ),
            (
                AccessPolicy::TreeKemEncrypted {
                    group_id: Vec::new(),
                },
                6,
            ),
        ];
        for (policy, index) in cases {
            let bytes = bincode::serialize(&policy).expect("serialize");
            assert!(bytes.len() >= 4, "bincode enum tag is a u32");
            let tag = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            assert_eq!(
                tag, index,
                "bincode discriminant for {policy} moved — this BREAKS every existing store/checkpoint"
            );
        }
    }

    // -----------------------------------------------------------------
    // AccessPolicy::SelfKeyed (issue #340) — owner-free open directories.
    // -----------------------------------------------------------------

    fn hex_key(agent: &AgentId, suffix: Option<&str>) -> String {
        match suffix {
            Some(s) => format!("{}/{}", hex::encode(agent.as_bytes()), s),
            None => hex::encode(agent.as_bytes()),
        }
    }

    fn self_keyed_store() -> KvStore {
        KvStore::new_self_keyed(store_id(9), "directory".to_string())
    }

    fn kv_entry(key: &str, val: &[u8]) -> KvEntry {
        KvEntry::new(key.to_string(), val.to_vec(), "text/plain".to_string())
    }

    #[test]
    fn key_agent_prefix_grammar() {
        // WHY (I1): the key prefix IS the write-authority binding. If the
        // grammar admitted ambiguous forms (uppercase, foreign separators,
        // short prefixes), one agent's namespace could collide with or be a
        // prefix of another's and the binding would be forgeable.
        let w = AgentId([0xab; 32]); // hex form contains letters a-f
        let hex_w = hex::encode(w.as_bytes());
        assert_eq!(hex_w.len(), 64);
        // Bare 64-hex key: the agent's root record.
        assert_eq!(key_agent_prefix(&hex_w), Some(w));
        // hex/suffix, including nested suffixes.
        assert_eq!(key_agent_prefix(&format!("{hex_w}/profile")), Some(w));
        assert_eq!(key_agent_prefix(&format!("{hex_w}/a/b")), Some(w));
        // Uppercase hex rejected.
        assert_eq!(key_agent_prefix(&hex_w.to_uppercase()), None);
        // Length < 64 rejected.
        assert_eq!(key_agent_prefix(&hex_w[..63]), None);
        assert_eq!(key_agent_prefix(""), None);
        // Length > 64 without the mandatory `/` at position 65 rejected.
        assert_eq!(key_agent_prefix(&format!("{hex_w}x")), None);
        // Any other separator rejected: one namespace is never a prefix of
        // another's.
        for sep in ['.', ':', '_', '-'] {
            assert_eq!(
                key_agent_prefix(&format!("{hex_w}{sep}x")),
                None,
                "separator {sep:?} must be rejected"
            );
        }
        // Non-hex characters rejected.
        let mut non_hex = hex_w.clone();
        non_hex.replace_range(0..1, "z");
        assert_eq!(key_agent_prefix(&non_hex), None);
    }

    /// #2068 point 2 (review of #2109): in a SelfKeyed directory, an
    /// `updated` entry for a key that is not live takes no quota slot.
    /// With the writer at its key cap, a stale update of a lower key must
    /// not push a live key out of the admitted set and evict it.
    #[test]
    fn selfkeyed_stale_update_takes_no_quota_slot() {
        let w = agent(7);
        let mut store = self_keyed_store();
        let mut fill = KvStoreDelta::new(0);
        for i in 1..=MAX_SELFKEYED_KEYS_PER_AGENT as u64 {
            let key = hex_key(&w, Some(&format!("{i:03}")));
            fill.added
                .insert(key.clone(), (kv_entry(&key, b"v"), (peer(1), i)));
        }
        store
            .merge_delta(&fill, peer(1), Some(&w))
            .expect("fill to the cap");
        assert_eq!(store.active_keys().len(), MAX_SELFKEYED_KEYS_PER_AGENT);

        let stale_key = hex_key(&w, Some("000"));
        let stale =
            KvStoreDelta::for_update(stale_key.clone(), kv_entry(&stale_key, b"s"), store.version);
        store
            .merge_delta(&stale, peer(1), Some(&w))
            .expect("the stale update is admitted");
        assert!(
            store.get(&stale_key).is_none(),
            "the stale key stays absent"
        );
        let last = hex_key(&w, Some(&format!("{MAX_SELFKEYED_KEYS_PER_AGENT:03}")));
        assert!(store.get(&last).is_some(), "the highest live key is kept");
        assert_eq!(store.active_keys().len(), MAX_SELFKEYED_KEYS_PER_AGENT);
    }

    #[test]
    fn selfkeyed_local_put_requires_own_prefix() {
        let me = agent(7);
        let other = agent(9);
        let mut store = self_keyed_store();

        // Own prefixed key and bare own root record are both writable.
        store
            .authorize_put(&me, &hex_key(&me, Some("profile")), b"v")
            .expect("own prefix writable");
        store
            .authorize_put(&me, &hex_key(&me, None), b"v")
            .expect("bare own root record writable");

        // Foreign prefix: Unauthorized — and never OwnerUnknown (I3: the
        // store deliberately has no owner for life).
        let err = store
            .authorize_put(&me, &hex_key(&other, Some("x")), b"v")
            .unwrap_err();
        assert!(matches!(err, KvError::Unauthorized(_)), "got {err:?}");

        // Malformed key: writable by no one.
        let err = store
            .authorize_put(&me, "not-a-bound-key", b"v")
            .unwrap_err();
        assert!(matches!(err, KvError::Unauthorized(_)), "got {err:?}");

        // The legacy key-less predicate fails closed for SelfKeyed.
        assert!(!store.is_authorized(&me));
        assert!(!store.is_authorized_for_key(&me, "anything"));
        assert!(store.is_authorized_for_key(&me, &hex_key(&me, None)));
        let err = store.authorize_local_write(&me).unwrap_err();
        assert!(
            matches!(err, KvError::Unauthorized(_)),
            "never OwnerUnknown: {err:?}"
        );

        // An authorized own-prefix put applies and reads back.
        let key = hex_key(&me, Some("profile"));
        store
            .put(
                key.clone(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        assert_eq!(store.get(&key).expect("entry").value, b"v");
        assert_eq!(store.owner(), None, "owner stays None for life (I3)");
        assert_eq!(*store.policy(), AccessPolicy::SelfKeyed);
    }

    #[test]
    fn selfkeyed_anonymous_delta_rejected() {
        // WHY (I5): a SelfKeyed directory binds writes to the verified
        // envelope sender; an anonymous delta has no identity to bind, so it
        // must apply NOTHING. Encrypted is independently fail-closed (#358).
        let w = agent(7);
        let mut store = self_keyed_store();
        let key = hex_key(&w, None);
        let mut delta = KvStoreDelta::new(1);
        delta
            .added
            .insert(key.clone(), (kv_entry(&key, b"v"), (peer(1), 1)));
        store
            .merge_delta(&delta, peer(1), None)
            .expect("silent whole-delta reject is not an error");
        assert!(
            store.get(&key).is_none(),
            "anonymous self_keyed delta applies nothing (I5)"
        );
        assert_eq!(store.current_version(), 0, "no state change");
        // Encrypted contrast omitted: #358 made Encrypted unconstructible
        // and fail-closed. Do not reopen construction here.
    }

    #[test]
    fn selfkeyed_merge_delta_applies_only_own_keys() {
        // WHY (I6): the envelope's verified sender is the only identity; a
        // writer cannot forge another agent's namespace, and keys outside
        // its prefix are dropped rather than applied.
        let w = agent(7);
        let other = agent(9);
        let mut store = self_keyed_store();
        let own = hex_key(&w, Some("a"));
        let foreign = hex_key(&other, Some("b"));
        let mut delta = KvStoreDelta::new(1);
        delta
            .added
            .insert(own.clone(), (kv_entry(&own, b"own"), (peer(1), 1)));
        delta.added.insert(
            foreign.clone(),
            (kv_entry(&foreign, b"foreign"), (peer(2), 1)),
        );
        // Allowlist mutations in the delta are ignored (I8).
        delta.allowlist_additions = Some(vec![other]);
        store.merge_delta(&delta, peer(1), Some(&w)).expect("merge");
        assert_eq!(store.get(&own).expect("own key applied").value, b"own");
        assert!(store.get(&foreign).is_none(), "foreign keys dropped (I6)");
        assert!(
            store.allowed_writers().is_empty(),
            "allowlist mutations are ignored"
        );
    }

    #[test]
    fn selfkeyed_foreign_tombstone_dropped() {
        let w = agent(7);
        let other = agent(9);
        let mut store = self_keyed_store();
        // Seed the other agent's key via its own legitimate delta.
        let other_key = hex_key(&other, Some("k"));
        let mut seed = KvStoreDelta::new(1);
        seed.added.insert(
            other_key.clone(),
            (kv_entry(&other_key, b"v"), (peer(2), 1)),
        );
        store
            .merge_delta(&seed, peer(2), Some(&other))
            .expect("seed");
        assert!(store.get(&other_key).is_some());

        // w attempts to tombstone other's key remotely: skipped.
        let mut delta = KvStoreDelta::new(2);
        delta.removed.insert(other_key.clone(), HashSet::new());
        store.merge_delta(&delta, peer(1), Some(&w)).expect("merge");
        assert!(
            store.get(&other_key).is_some(),
            "remote tombstone of a foreign key is dropped (I1)"
        );

        // Local counterpart: authorize_write refuses the foreign key.
        let err = store.authorize_write(&w, &other_key).unwrap_err();
        assert!(matches!(err, KvError::Unauthorized(_)), "got {err:?}");
    }

    #[test]
    fn selfkeyed_quota_enforced_local() {
        // WHY (I7): the quota is a deterministic admission rule, and the
        // local write path must use the SAME predicate as the remote merge
        // or a local write could diverge from what peers keep.
        let w = agent(7);
        let mut store = self_keyed_store();
        for i in 0..MAX_SELFKEYED_KEYS_PER_AGENT {
            let key = hex_key(&w, Some(&format!("{i:03}")));
            store
                .authorize_put(&w, &key, b"v")
                .expect("within the key cap");
            store
                .put(key, b"v".to_vec(), "text/plain".to_string(), peer(1))
                .expect("put");
        }
        // The 65th active key: AgentQuotaExceeded with key-count fields.
        let err = store
            .authorize_put(&w, &hex_key(&w, Some("065")), b"v")
            .unwrap_err();
        match &err {
            KvError::AgentQuotaExceeded {
                keys,
                bytes,
                max_keys,
                max_bytes,
                ..
            } => {
                assert_eq!(*keys, MAX_SELFKEYED_KEYS_PER_AGENT + 1);
                assert_eq!(*bytes, (MAX_SELFKEYED_KEYS_PER_AGENT + 1) as u64);
                assert_eq!(*max_keys, MAX_SELFKEYED_KEYS_PER_AGENT);
                assert_eq!(*max_bytes, MAX_SELFKEYED_BYTES_PER_AGENT);
            }
            other => panic!("expected AgentQuotaExceeded, got {other:?}"),
        }
        // The quota is per agent: a different agent's first key is unaffected.
        let other = agent(9);
        store
            .authorize_put(&other, &hex_key(&other, Some("a")), b"v")
            .expect("other agent unaffected");

        // Byte growth past 256 KiB trips the byte fields (4 max-size values
        // hit the cap exactly; a 5th exceeds it).
        let mut byte_store = self_keyed_store();
        let v = vec![0u8; crate::kv::entry::MAX_INLINE_SIZE];
        for i in 0..4 {
            let key = hex_key(&w, Some(&format!("{i}")));
            byte_store
                .authorize_put(&w, &key, &v)
                .expect("within the byte cap");
            byte_store
                .put(key, v.clone(), "text/plain".to_string(), peer(1))
                .expect("put");
        }
        let err = byte_store
            .authorize_put(&w, &hex_key(&w, Some("4")), b"x")
            .unwrap_err();
        match &err {
            KvError::AgentQuotaExceeded { keys, bytes, .. } => {
                assert_eq!(*keys, 5);
                assert_eq!(*bytes, MAX_SELFKEYED_BYTES_PER_AGENT + 1);
            }
            other => panic!("expected AgentQuotaExceeded, got {other:?}"),
        }

        // MAX_INLINE_SIZE still wins on a single oversized value.
        let err = store
            .authorize_put(
                &w,
                &hex_key(&w, Some("big")),
                &vec![0u8; crate::kv::entry::MAX_INLINE_SIZE + 1],
            )
            .unwrap_err();
        assert!(
            matches!(err, KvError::ValueTooLarge { .. }),
            "inline cap precedes the quota: {err:?}"
        );
    }

    #[test]
    fn selfkeyed_quota_lowest_n_converges() {
        // WHY (I7): "drop until under cap" is replica-order-dependent and
        // would split the directory. Lowest-N in lexicographic order is a
        // pure function of the live set, so two replicas fed the SAME 80
        // keys in DIFFERENT delivery orders must end with exactly the same
        // 64 lexicographically-lowest keys.
        let w = agent(7);
        let total = MAX_SELFKEYED_KEYS_PER_AGENT + 16; // 80
        let keys: Vec<String> = (0..total)
            .map(|i| hex_key(&w, Some(&format!("{i:03}"))))
            .collect();
        let deltas: Vec<KvStoreDelta> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let mut d = KvStoreDelta::new((i + 1) as u64);
                d.added
                    .insert(k.clone(), (kv_entry(k, b"v"), (peer(1), i as u64 + 1)));
                d
            })
            .collect();

        let mut forward = self_keyed_store();
        let mut reverse = self_keyed_store();
        for d in &deltas {
            forward
                .merge_delta(d, peer(1), Some(&w))
                .expect("forward merge");
        }
        for d in deltas.iter().rev() {
            reverse
                .merge_delta(d, peer(1), Some(&w))
                .expect("reverse merge");
        }

        let expected: Vec<String> = keys[..MAX_SELFKEYED_KEYS_PER_AGENT].to_vec();
        for (label, store) in [("forward", &forward), ("reverse", &reverse)] {
            let mut live: Vec<String> = store.active_keys().into_iter().cloned().collect();
            live.sort();
            assert_eq!(
                live, expected,
                "{label} replica must hold exactly the 64 lex-lowest keys"
            );
        }

        // Local-put counterpart (I7): `authorize_put` only gates the incoming
        // key, so `KvStore::put` must apply the same step-4 eviction or a
        // writer filling 64 lex-high keys and then putting a lex-low key
        // keeps 65 locally while every remote holds 64 — a local fork.
        let high: Vec<String> = (0..MAX_SELFKEYED_KEYS_PER_AGENT)
            .map(|i| hex_key(&w, Some(&format!("1{i:02}"))))
            .collect();
        let low = hex_key(&w, Some("050"));
        let mut local = self_keyed_store();
        for key in &high {
            local
                .authorize_put(&w, key, b"v")
                .expect("lex-high key within the key cap");
            local
                .put(
                    key.clone(),
                    b"v".to_vec(),
                    "text/plain".to_string(),
                    peer(1),
                )
                .expect("put");
        }
        local
            .authorize_put(&w, &low, b"v")
            .expect("lex-low key sorts into the admitted set");
        local
            .put(
                low.clone(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");

        // Second replica fed the SAME 65 keys through merge_delta, in the
        // opposite order (low first), must land on the identical 64.
        let mut remote = self_keyed_store();
        for (i, key) in std::iter::once(&low).chain(high.iter()).enumerate() {
            let mut d = KvStoreDelta::new((i + 1) as u64);
            d.added
                .insert(key.clone(), (kv_entry(key, b"v"), (peer(1), i as u64 + 1)));
            remote.merge_delta(&d, peer(1), Some(&w)).expect("merge");
        }

        let mut admitted: Vec<String> = high.clone();
        admitted.push(low.clone());
        admitted.sort();
        admitted.truncate(MAX_SELFKEYED_KEYS_PER_AGENT); // the lex-highest is evicted
        for (label, store) in [("local", &local), ("remote", &remote)] {
            let mut live: Vec<String> = store.active_keys().into_iter().cloned().collect();
            live.sort();
            assert_eq!(
                live, admitted,
                "{label} replica must hold exactly the admitted 64 after the local/remote split"
            );
        }
        assert!(local.get(&low).is_some(), "the new lex-low key stays");
        assert!(
            local.get(high.last().expect("64 high keys")).is_none(),
            "the lex-highest key is evicted locally, not only on remotes"
        );
    }

    /// The store half of `KvStoreHandle::put_with_outcome`: reserve a
    /// sequence and put. Returns the evicted keys it reports.
    fn put_reporting_evictions(store: &mut KvStore, key: String) -> Vec<String> {
        let seq = store.reserve_sequences(1).expect("reserve");
        store
            .put_with_reserved_sequence(key, b"v".to_vec(), "text/plain".to_string(), peer(1), seq)
            .expect("put")
    }

    /// Fill `w`'s SelfKeyed quota with keys `<w>/<i:03>` for `range`,
    /// going through `authorize_put` + put like the daemon's put path.
    fn fill_self_keyed(store: &mut KvStore, w: &AgentId, range: std::ops::Range<usize>) {
        for i in range {
            let key = hex_key(w, Some(&format!("{i:03}")));
            store.authorize_put(w, &key, b"v").expect("within quota");
            let evicted = put_reporting_evictions(store, key);
            assert!(evicted.is_empty(), "filling up to the cap evicts nothing");
        }
    }

    #[test]
    fn selfkeyed_over_quota_put_reports_exactly_the_evicted_key() {
        // WHY (#849): ADR-0047 lowest-N admission is kept, but the 65th put
        // used to evict the writer's lex-highest key with no signal. The put
        // must name exactly the key it evicted, and nothing else may go.
        let w = agent(7);
        let mut store = self_keyed_store();
        fill_self_keyed(&mut store, &w, 1..MAX_SELFKEYED_KEYS_PER_AGENT + 1);
        let low = hex_key(&w, Some("000"));
        store
            .authorize_put(&w, &low, b"v")
            .expect("a lex-low key is admitted");
        let evicted = put_reporting_evictions(&mut store, low.clone());
        let highest = hex_key(&w, Some(&format!("{MAX_SELFKEYED_KEYS_PER_AGENT:03}")));
        assert_eq!(
            evicted,
            vec![highest.clone()],
            "exactly the lex-highest key"
        );
        assert!(store.get(&highest).is_none(), "the reported key is gone");
        assert!(store.get(&low).is_some(), "the new key is stored");
        for i in 1..MAX_SELFKEYED_KEYS_PER_AGENT {
            assert!(
                store.get(&hex_key(&w, Some(&format!("{i:03}")))).is_some(),
                "unreported keys must survive: {i:03}"
            );
        }
        assert_eq!(store.active_keys().len(), MAX_SELFKEYED_KEYS_PER_AGENT);
    }

    #[test]
    fn selfkeyed_under_quota_put_reports_no_eviction() {
        // WHY (#849): a writer must be able to tell a harmless put from one
        // that cost it a key, so an under-quota put reports an empty list.
        let w = agent(7);
        let mut store = self_keyed_store();
        fill_self_keyed(&mut store, &w, 0..MAX_SELFKEYED_KEYS_PER_AGENT - 1);
        let key = hex_key(&w, Some("999"));
        store
            .authorize_put(&w, &key, b"v")
            .expect("the 64th key fits");
        let evicted = put_reporting_evictions(&mut store, key);
        assert!(evicted.is_empty(), "no eviction under quota: {evicted:?}");
        assert_eq!(store.active_keys().len(), MAX_SELFKEYED_KEYS_PER_AGENT);
    }

    #[test]
    fn selfkeyed_new_highest_key_is_not_admitted_and_evicts_nothing() {
        // WHY (#849 + ADR-0047): when the new key itself sorts last, the
        // lowest-N rule refuses it rather than evicting a live key. The
        // refusal must say the key was not admitted, and every existing
        // key must survive.
        let w = agent(7);
        let mut store = self_keyed_store();
        fill_self_keyed(&mut store, &w, 0..MAX_SELFKEYED_KEYS_PER_AGENT);
        let before: HashSet<String> = store.active_keys().into_iter().cloned().collect();
        let err = store
            .authorize_put(&w, &hex_key(&w, Some("999")), b"v")
            .expect_err("a new lex-highest key over quota is refused");
        assert!(matches!(err, KvError::AgentQuotaExceeded { .. }), "{err:?}");
        assert!(
            err.to_string().contains("NOT admitted"),
            "the refusal must state the key was not admitted: {err}"
        );
        let after: HashSet<String> = store.active_keys().into_iter().cloned().collect();
        assert_eq!(after, before, "a refused put evicts nothing");
    }

    #[test]
    fn selfkeyed_quota_freed_by_remove() {
        // WHY: tombstones must free budget — and a single delta must be able
        // to free and spend in one message (tombstones apply before puts).
        let w = agent(7);
        let mut store = self_keyed_store();
        for i in 0..MAX_SELFKEYED_KEYS_PER_AGENT {
            store
                .put(
                    hex_key(&w, Some(&format!("{i:03}"))),
                    b"v".to_vec(),
                    "text/plain".to_string(),
                    peer(1),
                )
                .expect("put");
        }
        // At the cap: a 65th key is refused.
        store
            .authorize_put(&w, &hex_key(&w, Some("999")), b"v")
            .unwrap_err();
        // An own tombstone frees count and bytes.
        store
            .remove(&hex_key(&w, Some("000")))
            .expect("own remove frees budget");
        store
            .authorize_put(&w, &hex_key(&w, Some("999")), b"v")
            .expect("quota freed by own tombstone");

        // Remote apply-order: bring a replica to the cap, then one delta
        // tombstones a key AND adds a fresh key.
        let mut replica = self_keyed_store();
        for i in 0..MAX_SELFKEYED_KEYS_PER_AGENT {
            let key = hex_key(&w, Some(&format!("{i:03}")));
            let mut d = KvStoreDelta::new(i as u64 + 1);
            d.added
                .insert(key.clone(), (kv_entry(&key, b"v"), (peer(1), i as u64 + 1)));
            replica
                .merge_delta(&d, peer(1), Some(&w))
                .expect("seed replica");
        }
        let mut d = KvStoreDelta::new(99);
        d.removed.insert(hex_key(&w, Some("000")), HashSet::new());
        d.added.insert(
            hex_key(&w, Some("999")),
            (kv_entry(&hex_key(&w, Some("999")), b"v"), (peer(1), 99)),
        );
        replica
            .merge_delta(&d, peer(1), Some(&w))
            .expect("tombstone frees budget within one delta");
        assert!(replica.get(&hex_key(&w, Some("000"))).is_none());
        assert!(replica.get(&hex_key(&w, Some("999"))).is_some());
    }

    #[test]
    fn selfkeyed_store_id_deterministic_and_domain_separated() {
        // WHY (I2): joiners know only the topic; the id must be derivable
        // from the topic alone, identical on every peer, and never collide
        // with an owner-anchored derivation of the same topic string.
        let owner = agent(1);
        let a = KvStoreId::for_self_keyed_topic("directory/topic");
        let b = KvStoreId::for_self_keyed_topic("directory/topic");
        assert_eq!(a, b, "same topic ⇒ same id on every peer (I2)");
        assert_ne!(a, KvStoreId::for_self_keyed_topic("other"));
        assert_ne!(
            a,
            KvStoreId::for_topic_owner("directory/topic", &owner),
            "domain-separated from the owner-anchored derivation"
        );
        assert_ne!(
            a,
            KvStoreId::from_content("directory/topic", &owner),
            "domain-separated from the legacy derivation"
        );
    }

    #[test]
    fn selfkeyed_no_owner_checkpoint_and_no_prune() {
        // WHY (I8): the store has no owner, so no checkpoint can be adopted
        // and no peer's full serve may truncate a co-writer's key — a serve
        // can legitimately omit keys this replica holds from another writer.
        let w1 = agent(7);
        let w2 = agent(9);
        let mut store = self_keyed_store();
        for (writer, suffix) in [(&w1, "a"), (&w2, "b")] {
            let key = hex_key(writer, Some(suffix));
            let mut d = KvStoreDelta::new(1);
            d.added
                .insert(key.clone(), (kv_entry(&key, b"v"), (peer(1), 1)));
            store.merge_delta(&d, peer(1), Some(writer)).expect("merge");
            assert!(store.get(&key).is_some());
        }
        // A delta carrying an (unverifiable) owner checkpoint is ignored:
        // no owner exists to verify against, nothing adopted.
        let mut cp_delta = KvStoreDelta::new(2);
        cp_delta.owner_checkpoint = Some(OwnerCheckpoint {
            topic: "directory".to_string(),
            store_id: store_id(9),
            owner_pubkey: Vec::new(),
            policy: AccessPolicy::Signed,
            policy_version: 9,
            checkpoint_seq: 9,
            content_root: [0u8; 32],
            timestamp: 0,
            signature: Vec::new(),
        });
        store
            .merge_delta(&cp_delta, peer(1), Some(&w1))
            .expect("checkpoint ignored");
        assert!(
            store.latest_checkpoint.is_none(),
            "no OwnerCheckpoint is ever adopted (I8)"
        );
        assert_eq!(store.highest_checkpoint_seq, 0);
        assert_eq!(store.owner(), None);

        // A digest-verified-style full serve from w1 must NOT truncate w2's
        // key: prune_to_served_set is a no-op on SelfKeyed (mirrors the
        // Allowlisted sole-author rule — a peer's serve can omit
        // co-writers' keys).
        let w1_key = hex_key(&w1, Some("a"));
        let mut serve = KvStoreDelta::new(3);
        serve
            .added
            .insert(w1_key.clone(), (kv_entry(&w1_key, b"v"), (peer(1), 2)));
        assert_eq!(
            store.prune_to_served_set(&serve),
            0,
            "prune is a no-op for self_keyed"
        );
        assert!(
            store.get(&hex_key(&w2, Some("b"))).is_some(),
            "a co-writer's key survives another writer's full serve"
        );
    }

    #[test]
    fn selfkeyed_owner_announce_and_allowlist_ignored() {
        // WHY (I8): ownership and the allowlist are owner-anchored concepts;
        // a SelfKeyed store has no owner for life, so every such path must
        // fail closed without mutating policy, owner, or the allowlist.
        let mut store = self_keyed_store();
        let claimant = agent(7);
        // A self-announced ownership claim is rejected — ownership is
        // construction-only and this store deliberately has none.
        let err = store
            .learn_ownership(claimant, AccessPolicy::Signed, 99, &claimant)
            .unwrap_err();
        assert!(matches!(err, KvError::OwnerTokenInvalid(_)));
        assert_eq!(store.owner(), None);
        assert_eq!(*store.policy(), AccessPolicy::SelfKeyed, "policy immutable");

        // Allowlist mutations are owner-only and this store has no owner.
        let err = store.allow_writer(claimant, &claimant).unwrap_err();
        assert!(matches!(err, KvError::Unauthorized(_)), "got {err:?}");
        let err = store.deny_writer(&claimant, &claimant).unwrap_err();
        assert!(matches!(err, KvError::Unauthorized(_)), "got {err:?}");
        assert!(store.allowed_writers().is_empty());
    }
}

#[cfg(test)]
#[path = "incremental_measure_tests.rs"]
mod incremental_measure_tests;

#[cfg(test)]
#[path = "orset_undo_tests.rs"]
mod orset_undo_tests;
