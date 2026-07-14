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
//! - **Encrypted**: Reserved for group-scoped encrypted stores. The current
//!   KvStore sync path does not encrypt deltas; do not rely on this policy for
//!   confidentiality until encrypted sync is wired.

use crate::identity::AgentId;
use crate::kv::{KvEntry, KvError, KvStoreDelta, Result};
use saorsa_gossip_crdt_sync::{LwwRegister, OrSet};
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Access control policy for a KvStore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessPolicy {
    /// Only the owner can write. Anyone can read and replicate.
    /// Incoming deltas from non-owners are silently rejected.
    Signed,

    /// Only explicitly allowlisted agents can write.
    /// The owner manages the allowlist.
    Allowlisted,

    /// Reserved for group-scoped encrypted stores.
    ///
    /// The current KvStore sync path still publishes plaintext deltas and does
    /// not enforce group membership by itself. Do not rely on this variant for
    /// confidentiality until encrypted sync is wired.
    Encrypted {
        /// MLS group ID for this store.
        group_id: Vec<u8>,
    },
}

impl std::fmt::Display for AccessPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signed => write!(f, "signed"),
            Self::Allowlisted => write!(f, "allowlisted"),
            Self::Encrypted { .. } => write!(f, "encrypted"),
        }
    }
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
fn lp_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
    buf.extend_from_slice(data);
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

/// A replicated key-value store using CRDTs with access control.
///
/// Combines:
/// - OR-Set for key membership (which keys exist)
/// - HashMap for entry content (the KvEntry values)
/// - LWW-Register for store metadata (name)
/// - Access control via owner, allowlist, and policy
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Monotonic sequence counter for unique OR-Set tags.
    #[serde(skip, default = "default_seq_counter")]
    seq_counter: Arc<AtomicU64>,
}

/// Deserialize a trailing, defaultable `KvStore` field, tolerating its absence.
///
/// bincode is positional and non-self-describing: a blob written by an older
/// `KvStore` shape simply ends before these trailing fields, so bincode hits
/// EOF when asked to read them. Decoding the value if present, or falling back
/// to `T::default()` on EOF / any malformed tail, makes such a blob load with
/// the newer fields defaulted rather than failing outright. Only sound at
/// stream-EOF for genuinely trailing fields (see the struct's TRAILING note).
fn de_tolerant<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de> + Default,
{
    Ok(T::deserialize(deserializer).unwrap_or_default())
}

fn default_policy() -> AccessPolicy {
    AccessPolicy::Signed
}

impl KvStore {
    /// Create a new empty KvStore with the given access policy.
    /// Create a new empty KvStore owned by `owner` with the given access
    /// policy.
    ///
    /// This is the **creator** path: ownership is anchored on `owner` at
    /// construction (channel [`AnchorChannel::Creator`]) and is immutable for
    /// the life of the store.
    #[must_use]
    pub fn new(id: KvStoreId, name: String, owner: AgentId, policy: AccessPolicy) -> Self {
        let mut name_reg = LwwRegister::new(name.clone());
        // Stamp the creator-set name with a non-empty clock so it wins LWW
        // merge against replicas initialized with empty names and empty
        // clocks (which would otherwise be concurrent and hash-tiebroken).
        name_reg.set(name, PeerId::new(owner.0));
        Self {
            id,
            keys: OrSet::new(),
            entries: HashMap::new(),
            name: name_reg,
            policy,
            owner: Some(owner),
            anchor_channel: AnchorChannel::Creator,
            policy_version: 0,
            ownership_conflict: None,
            latest_checkpoint: None,
            highest_checkpoint_seq: 0,
            allowed_writers: HashSet::new(),
            version: 0,
            seq_counter: Arc::new(AtomicU64::new(0)),
        }
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
            latest_checkpoint: None,
            highest_checkpoint_seq: 0,
            allowed_writers: HashSet::new(),
            version: 0,
            seq_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get the next monotonically-increasing sequence number.
    pub fn next_seq(&self) -> u64 {
        self.seq_counter.fetch_add(1, Ordering::Relaxed) + 1
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
            AccessPolicy::Encrypted { .. } => {
                // Reserved for encrypted sync. The store layer currently treats
                // this as permissive; group membership enforcement belongs in
                // the secure sync path once wired.
                true
            }
        }
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
    /// - [`KvError::OwnerUnknown`] if the store has a policy-restricted
    ///   (`Signed`/`Allowlisted`) policy but its authoritative owner has not
    ///   been learned yet (a freshly joined replica). Fail closed.
    /// - [`KvError::Unauthorized`] if `writer` is not authorized under the
    ///   store's policy.
    pub fn authorize_local_write(&self, writer: &AgentId) -> Result<()> {
        if matches!(self.policy, AccessPolicy::Encrypted { .. }) {
            // Matches the inbound path: the reserved Encrypted policy is
            // currently permissive at the store layer.
            return Ok(());
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
            // Immutable owner: record the conflict for auditability and reject.
            self.ownership_conflict = Some((existing, claimed_owner));
            self.version += 1;
            return Err(KvError::OwnershipConflict {
                anchored: existing,
                claimed: claimed_owner,
            });
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
        if policy_version >= self.policy_version {
            self.policy = policy;
            self.policy_version = policy_version;
            self.ownership_conflict = None;
            self.version += 1;
        }
        Ok(())
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
        self.version += 1;
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
        self.version += 1;
        Ok(())
    }

    /// Put a key-value entry.
    ///
    /// If the key already exists, the value is updated using LWW semantics.
    pub fn put(
        &mut self,
        key: String,
        value: Vec<u8>,
        content_type: String,
        peer_id: PeerId,
    ) -> Result<()> {
        if value.len() > crate::kv::entry::MAX_INLINE_SIZE {
            return Err(KvError::ValueTooLarge {
                size: value.len(),
                max: crate::kv::entry::MAX_INLINE_SIZE,
            });
        }

        let seq = self.next_seq();

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

        self.version += 1;
        Ok(())
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

    /// Remove a key from the store.
    pub fn remove(&mut self, key: &str) -> Result<()> {
        if !self.entries.contains_key(key) {
            return Err(KvError::KeyNotFound(key.to_string()));
        }

        self.keys
            .remove(&key.to_string())
            .map_err(|e| KvError::Merge(format!("OR-Set remove failed: {e}")))?;
        self.entries.remove(key);

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
        self.version += 1;
    }

    /// Merge a delta into this store.
    ///
    /// Enforces access control: if the store has a Signed or Allowlisted
    /// policy, the `writer` must be authorized. Unauthorized deltas are
    /// silently rejected (returns Ok but does not apply changes).
    pub fn merge_delta(
        &mut self,
        delta: &KvStoreDelta,
        peer_id: PeerId,
        writer: Option<&AgentId>,
    ) -> Result<()> {
        // Authoritative full-snapshot checkpoint adoption (cold-recovery path):
        // if the checkpoint's content root matches the relayed entry set, adopt
        // as owner-proven independent of the relayer. An incremental delta's
        // single-entry set won't match a full-state root, so it falls through
        // to the sender-auth path below (where the owner is authorized as
        // writer==owner), and the checkpoint is cached afterward by
        // maybe_cache_checkpoint if the resulting state matches.
        if let Some(cp) = delta.owner_checkpoint.as_ref() {
            if self.try_adopt_full_snapshot(delta, peer_id, cp) {
                return Ok(());
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
                return Ok(());
            }
        }
        // Access control: reject unauthorized writes
        if let Some(writer_id) = writer {
            if !self.is_authorized(writer_id) {
                tracing::warn!(
                    "rejected delta from unauthorized writer {} for store {}",
                    hex::encode(writer_id.as_bytes()),
                    self.id
                );
                return Ok(()); // Silent rejection — don't propagate errors for spam
            }
        } else {
            // No writer identity is only tolerated for the reserved Encrypted
            // policy. KvStoreSync does not decrypt or verify group membership
            // here today.
            match &self.policy {
                AccessPolicy::Encrypted { .. } => {} // OK
                _ => {
                    tracing::warn!(
                        "rejected anonymous delta for non-encrypted store {}",
                        self.id
                    );
                    return Ok(());
                }
            }
        }

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
            self.keys
                .add(key.clone(), *tag)
                .map_err(|e| KvError::Merge(format!("OR-Set add failed: {e}")))?;

            if let Some(existing) = self.entries.get_mut(key) {
                existing.merge(entry);
            } else {
                self.entries.insert(key.clone(), entry.clone());
            }
        }

        // Apply removed keys
        for key in delta.removed.keys() {
            let _ = self.keys.remove(&key.to_string());
            self.entries.remove(key.as_str());
        }

        // Apply updated entries (upsert)
        for (key, entry) in &delta.updated {
            if let Some(existing) = self.entries.get_mut(key) {
                existing.merge(entry);
            } else {
                self.keys
                    .add(key.clone(), (peer_id, 0))
                    .map_err(|e| KvError::Merge(format!("OR-Set add failed: {e}")))?;
                self.entries.insert(key.clone(), entry.clone());
            }
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
        Ok(())
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
    /// Returns `false` otherwise (unanchored, bad sig/owner, stale seq,
    /// cross-store, entry integrity failure, root mismatch / incremental
    /// delta / tamper), in which case [`merge_delta`] falls through to the
    /// normal sender-auth path. Never establishes ownership (anchor gate).
    fn try_adopt_full_snapshot(
        &mut self,
        delta: &KvStoreDelta,
        peer_id: PeerId,
        cp: &OwnerCheckpoint,
    ) -> bool {
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
        // 7. Adopt: merge the entries as owner-authorized (bypass sender-auth).
        for (key, (entry, tag)) in &delta.added {
            let _ = self.keys.add(key.clone(), *tag);
            if let Some(existing) = self.entries.get_mut(key) {
                existing.merge(entry);
            } else {
                self.entries.insert(key.clone(), entry.clone());
            }
        }
        for (key, entry) in &delta.updated {
            if let Some(existing) = self.entries.get_mut(key) {
                existing.merge(entry);
            } else {
                let _ = self.keys.add(key.clone(), (peer_id, 0));
                self.entries.insert(key.clone(), entry.clone());
            }
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
            self.entries.remove(&key);
        }
        // 9. Apply name update.
        if let Some(name_register) = &delta.name_update {
            self.name.merge(name_register);
        }
        // 10. Refresh policy (forward only) and cache the checkpoint.
        if cp.policy_version >= self.policy_version {
            self.policy = cp.policy.clone();
            self.policy_version = cp.policy_version;
        }
        self.latest_checkpoint = Some(cp.clone());
        self.highest_checkpoint_seq = cp.checkpoint_seq;
        self.version += 1;
        true
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
        // Cache only if the resulting complete state matches the checkpoint.
        let matches = {
            let pairs = self.checkpoint_pairs();
            content_root(&self.id, self.name(), &pairs) == cp.content_root
        };
        if matches {
            self.latest_checkpoint = Some(cp.clone());
            self.highest_checkpoint_seq = cp.checkpoint_seq;
        }
    }

    /// Merge another store into this one.
    pub fn merge(&mut self, other: &KvStore) -> Result<()> {
        if self.id != other.id {
            return Err(KvError::StoreIdMismatch);
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

    /// Generate a delta containing all state (for initial sync).
    #[must_use]
    pub fn full_delta(&self) -> KvStoreDelta {
        let mut delta = KvStoreDelta::new(self.version);

        // Walk the active-key OR-Set directly and look entries up, rather than
        // cloning the whole key set into an intermediate HashSet first.
        for key in self.keys.elements() {
            if let Some(entry) = self.entries.get(key) {
                let tag = (PeerId::new([0u8; 32]), 0);
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
        delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    fn peer(n: u8) -> PeerId {
        PeerId::new([n; 32])
    }

    fn store_id(n: u8) -> KvStoreId {
        KvStoreId::new([n; 32])
    }

    #[test]
    fn test_new_store() {
        let owner = agent(1);
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed);
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
        );

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
        );

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
        );

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
        );
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
        );
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
        );

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

        let mut s1 = KvStore::new(id, "Store".to_string(), owner, AccessPolicy::Signed);
        let mut s2 = KvStore::new(id, "Store".to_string(), owner, AccessPolicy::Signed);

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
        let mut s1 = KvStore::new(store_id(1), "A".to_string(), owner, AccessPolicy::Signed);
        let s2 = KvStore::new(store_id(2), "B".to_string(), owner, AccessPolicy::Signed);
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
        );
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
        );
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
        );
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
        );
        let s1 = store.next_seq();
        let s2 = store.next_seq();
        assert!(s2 > s1);
    }

    // -- Access control tests --

    #[test]
    fn test_signed_policy_owner_authorized() {
        let owner = agent(1);
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed);
        assert!(store.is_authorized(&owner));
    }

    #[test]
    fn test_signed_policy_non_owner_rejected() {
        let owner = agent(1);
        let other = agent(2);
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed);
        assert!(!store.is_authorized(&other));
    }

    #[test]
    fn test_signed_policy_rejects_unauthorized_delta() {
        let owner = agent(1);
        let attacker = agent(99);
        let mut store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed);

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
        let mut store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed);

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
        );

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
        );

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
        );

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
        );
        store.allow_writer(writer, &owner).expect("allow");

        // Full delta should include the allowlist
        let delta = store.full_delta();
        assert!(delta.allowlist_additions.is_some());
        assert!(delta
            .allowlist_additions
            .as_ref()
            .is_some_and(|a| a.contains(&writer)));
    }

    #[test]
    fn test_anonymous_delta_rejected_for_signed_store() {
        let owner = agent(1);
        let mut store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed);

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
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed);
        store
            .authorize_local_write(&owner)
            .expect("owner must be able to write locally");
    }

    #[test]
    fn test_local_write_non_owner_rejected_on_signed_store() {
        let owner = agent(1);
        let joiner = agent(2);
        let store = KvStore::new(store_id(1), "Test".to_string(), owner, AccessPolicy::Signed);
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
            KvStore::new(store_id(1), "S".to_string(), owner, AccessPolicy::Signed);
        owner_store
            .put(
                "k".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("owner put");
        let full = owner_store.full_delta();
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
    fn test_local_write_encrypted_policy_stays_permissive() {
        // The reserved Encrypted policy is permissive at the store layer on
        // the inbound path; the local path must match it, not diverge.
        let store = KvStore::new(
            store_id(1),
            "Test".to_string(),
            agent(1),
            AccessPolicy::Encrypted { group_id: vec![1] },
        );
        store
            .authorize_local_write(&agent(9))
            .expect("encrypted policy is permissive at the store layer");
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

        let mut owner_store = KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed);
        owner_store
            .put(
                "k".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let cp = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut delta = owner_store.full_delta();
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
    fn full_replace_ignores_relay_injected_removed() {
        // A non-owner relay copies the owner's valid full-snapshot checkpoint of
        // {k} and injects removed={k}. The full-replace adopt path IGNORES the
        // untrusted `delta.removed` — the owner-signed set {k} is authoritative —
        // so the injection cannot truncate the joiner's recovered state.
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let owner = kp.agent_id();
        let topic = "store/inject";
        let id = KvStoreId::for_topic_owner(topic, &owner);
        let mut owner_store = KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed);
        owner_store
            .put(
                "k".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let cp = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut delta = owner_store.full_delta();
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
        let mut owner_store = KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed);
        owner_store
            .put(
                "k1".to_string(),
                b"alpha".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put k1");
        let cp1 = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut stale_delta = owner_store.full_delta();
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
        let mut snapshot = owner_store.full_delta();
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
        let mut owner_store = KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed);
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
        let mut d1 = owner_store.full_delta();
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
        let mut d2 = owner_store.full_delta();
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
        let mut owner_store = KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed);
        owner_store
            .put(
                "k".to_string(),
                b"v".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let cp = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut delta = owner_store.full_delta();
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
        let owner_store = KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed);
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
        let owner_store = KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed);
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
        let owner_store = KvStore::new(id_a, "A".to_string(), owner, AccessPolicy::Signed);
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
        let mut owner_store = KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed);
        owner_store
            .put(
                "k".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
                peer(1),
            )
            .expect("put");
        let cp1 = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut relay = owner_store.full_delta();
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
        let mut full2 = owner_store.full_delta();
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
        let mut delta =
            KvStoreDelta::for_put(key.to_string(), entry, (p, owner.next_seq()), version);
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

        let mut owner_store = KvStore::new(id, "Legit".to_string(), owner, AccessPolicy::Signed);
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
            let mut legit = owner_store.full_delta();
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
            let mut delta = owner_store.full_delta();
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

        let mut owner_store = KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed);
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

        let mut owner_store = KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed);
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
        let relay_full = relay.full_delta();
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

        let mut owner_store = KvStore::new(id, "S".to_string(), owner, AccessPolicy::Signed);
        owner_store
            .put("k".to_string(), b"v".to_vec(), "text/plain".to_string(), p)
            .expect("owner put");
        let cp1 = checkpoint_for(&owner_store, topic, &kp, 1);
        let mut snap1 = owner_store.full_delta();
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
        let mut snap2 = owner_store.full_delta();
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
}
