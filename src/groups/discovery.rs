//! Distributed discovery index (Phase C.2).
//!
//! Partition-tolerant, DHT-free group discovery using sharded gossip
//! topics. Design source of truth:
//! `docs/design/named-groups-full-model.md` §"Distributed Discovery Index".
//!
//! Three shard kinds:
//!
//! - **Tag shards** — `x0x.directory.tag.{N}` where
//!   `N = BLAKE3("x0x-group-tag" || lowercase(tag)) % 65536`.
//! - **Name shards** — `x0x.directory.name.{N}` where
//!   `N = BLAKE3("x0x-group-name" || lowercase(word)) % 65536`, one
//!   shard per whitespace-delimited word in the group name.
//! - **Exact-ID shards** — `x0x.directory.id.{N}` where
//!   `N = BLAKE3("x0x-group-id" || group_id) % 65536`. Used only for
//!   `PublicDirectory` groups (never for `Hidden` or
//!   `ListedToContacts`, per privacy rules).
//!
//! Messages on every shard topic are [`DirectoryMessage`] variants:
//! - `Card` — signed `GroupCard` data-plane payload.
//! - `Digest` — anti-entropy summary of known entries.
//! - `Pull` — request missing/stale cards from peers.
//!
//! Receivers de-duplicate by `group_id`, keeping the highest valid
//! signed revision. TTL is only cache cleanup, not the primary
//! validity mechanism — D.3 signed `GroupCard::supersedes` drives
//! immediate replacement.

use crate::groups::directory::{CardRefusal, CardReplacement, GroupCard};
use crate::groups::policy::GroupDiscoverability;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Number of shards per shard kind. 65,536 = 16-bit space, plenty of room
/// to amortise popular tags/names across many peers.
pub const SHARD_COUNT: u32 = 65_536;

/// Domain-separation tag for tag-shard computation.
pub const TAG_DOMAIN: &[u8] = b"x0x-group-tag";

/// Domain-separation tag for name-shard computation.
pub const NAME_DOMAIN: &[u8] = b"x0x-group-name";

/// Domain-separation tag for exact-id-shard computation.
pub const ID_DOMAIN: &[u8] = b"x0x-group-id";

/// Topic prefix for directory shards.
pub const DIRECTORY_TOPIC_PREFIX: &str = "x0x.directory";

/// Maximum number of shards a single daemon subscribes to by default.
/// Bounds memory and anti-entropy load. Users can raise via config if
/// they intentionally want to index more of the public directory.
pub const DEFAULT_MAX_SUBSCRIPTIONS: usize = 512;

/// Maximum entries kept in a single shard cache. Bounded LRU.
pub const DEFAULT_MAX_ENTRIES_PER_SHARD: usize = 4_096;

/// Maximum number of tags a group may publish on (hot-tag mitigation).
pub const MAX_TAGS_PER_GROUP: usize = 16;

/// Maximum number of name words a group may fan out on.
pub const MAX_NAME_WORDS: usize = 8;

// ────────────────────────── Shard computation ───────────────────────────

/// Kind of directory shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardKind {
    Tag,
    Name,
    Id,
}

impl ShardKind {
    /// Domain-separation bytes for this kind.
    #[must_use]
    pub fn domain(self) -> &'static [u8] {
        match self {
            Self::Tag => TAG_DOMAIN,
            Self::Name => NAME_DOMAIN,
            Self::Id => ID_DOMAIN,
        }
    }

    /// Human-readable name used in topic strings.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tag => "tag",
            Self::Name => "name",
            Self::Id => "id",
        }
    }

    /// Parse from a string slice. Case-insensitive.
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tag" => Some(Self::Tag),
            "name" => Some(Self::Name),
            "id" => Some(Self::Id),
            _ => None,
        }
    }
}

/// Compute the shard index for a given `(kind, key)` pair. The `key` is
/// the **already-normalised** input (lowercased tag/name-word, or
/// raw `group_id` for the id shard).
#[must_use]
pub fn shard_of(kind: ShardKind, key: &str) -> u32 {
    let mut buf = Vec::with_capacity(kind.domain().len() + key.len() + 1);
    buf.extend_from_slice(kind.domain());
    buf.push(b'|');
    buf.extend_from_slice(key.as_bytes());
    let hash = blake3::hash(&buf);
    let bytes = hash.as_bytes();
    let n = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    n % SHARD_COUNT
}

/// Topic string for a shard.
#[must_use]
pub fn topic_for(kind: ShardKind, shard: u32) -> String {
    format!("{}.{}.{}", DIRECTORY_TOPIC_PREFIX, kind.as_str(), shard)
}

/// Normalise a tag: lowercase, trimmed.
#[must_use]
pub fn normalize_tag(tag: &str) -> String {
    tag.trim().to_lowercase()
}

/// Normalise the group name into searchable words. Whitespace-split,
/// lowercased, short-word (< 2 chars) filtered.
#[must_use]
pub fn name_words(name: &str) -> Vec<String> {
    let mut words: Vec<String> = name
        .split_whitespace()
        .filter_map(|w| {
            let w = w
                .trim_matches(|c: char| !c.is_alphanumeric())
                .to_lowercase();
            if w.len() >= 2 {
                Some(w)
            } else {
                None
            }
        })
        .collect();
    words.sort();
    words.dedup();
    words.truncate(MAX_NAME_WORDS);
    words
}

/// Compute the full set of shards a `PublicDirectory` group publishes to,
/// given its (already-normalised) tags, name, and stable `group_id`.
///
/// Returns a deterministic, deduplicated list of `(kind, shard, key)`
/// triples. The `key` is the normalised token; callers may use it for
/// debugging/logging.
#[must_use]
pub fn shards_for_public(
    tags: &[String],
    name: &str,
    group_id: &str,
) -> Vec<(ShardKind, u32, String)> {
    let mut out: Vec<(ShardKind, u32, String)> = Vec::new();

    // Tag shards — cap at MAX_TAGS_PER_GROUP.
    let mut tag_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for raw in tags.iter().take(MAX_TAGS_PER_GROUP) {
        let t = normalize_tag(raw);
        if t.is_empty() || !tag_seen.insert(t.clone()) {
            continue;
        }
        out.push((ShardKind::Tag, shard_of(ShardKind::Tag, &t), t));
    }

    // Name-word shards — cap at MAX_NAME_WORDS.
    for word in name_words(name) {
        out.push((ShardKind::Name, shard_of(ShardKind::Name, &word), word));
    }

    // Exact-ID shard — exactly one entry.
    out.push((
        ShardKind::Id,
        shard_of(ShardKind::Id, group_id),
        group_id.to_string(),
    ));

    out
}

/// Decide whether a group may publish to **public** shards at all.
///
/// Privacy contract from the design doc:
/// - `Hidden` — must never leak to any public discovery surface.
/// - `ListedToContacts` — must never publish to public tag/name/id
///   shards. Uses contact-scoped pairwise sync instead (see
///   [`ListedToContactsDigest`]).
/// - `PublicDirectory` — may publish to all three shard kinds.
#[must_use]
pub fn may_publish_to_public_shards(discoverability: GroupDiscoverability) -> bool {
    matches!(discoverability, GroupDiscoverability::PublicDirectory)
}

// ────────────────────────── Wire messages ───────────────────────────────

/// Anti-entropy digest for a single cached group entry. Minimum set of
/// fields per design: `group_id`, `revision`, `state_hash`, `expires_at`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DigestEntry {
    pub group_id: String,
    pub revision: u64,
    pub state_hash: String,
    pub expires_at: u64,
}

impl DigestEntry {
    /// Build a digest entry from a signed card.
    #[must_use]
    pub fn from_card(card: &GroupCard) -> Self {
        Self {
            group_id: card.group_id.clone(),
            revision: card.revision,
            state_hash: card.state_hash.clone(),
            expires_at: card.expires_at,
        }
    }
}

/// Messages carried on `x0x.directory.{kind}.{shard}` topics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "m", rename_all = "snake_case")]
pub enum DirectoryMessage {
    /// Signed card — data plane.
    Card {
        /// The signed card. Receiver must verify the authority signature
        /// before caching.
        card: Box<GroupCard>,
    },
    /// Advertise known entries on this shard — AE summary.
    Digest {
        shard: u32,
        kind: ShardKind,
        entries: Vec<DigestEntry>,
    },
    /// Request the holder to (re)publish specific group_ids this peer
    /// observed in a digest but does not hold, or holds at a stale
    /// revision.
    Pull {
        shard: u32,
        kind: ShardKind,
        group_ids: Vec<String>,
    },
}

impl DirectoryMessage {
    /// Serialize for gossip.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Parse an incoming payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

// ────────────────────────── Shard cache ─────────────────────────────────

/// Bounded in-memory cache of signed cards keyed by `group_id`, keeping
/// only the highest-revision valid card per id. Used by subscribed
/// shards.
///
/// Capacity is enforced per-shard via LRU eviction on insert. Withdrawal
/// cards cause immediate eviction regardless of revision ordering.
#[derive(Debug)]
pub struct DirectoryShardCache {
    /// Max entries per shard before LRU eviction kicks in.
    capacity: usize,
    /// Per-shard `group_id → card`.
    ///
    /// Key: `(kind, shard)`. Value: BTreeMap (ordered by group_id for
    /// deterministic digest emission).
    shards: BTreeMap<(ShardKind, u32), BTreeMap<String, GroupCard>>,
    /// Recency order per shard for LRU eviction.
    recency: BTreeMap<(ShardKind, u32), Vec<String>>,
}

impl Default for DirectoryShardCache {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES_PER_SHARD)
    }
}

impl DirectoryShardCache {
    /// Create an empty cache with the given per-shard capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            shards: BTreeMap::new(),
            recency: BTreeMap::new(),
        }
    }

    /// Number of shards this cache currently tracks.
    #[must_use]
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Insert a signed card into a shard. Returns `true` if the card was
    /// accepted (higher-or-equal revision vs any existing entry).
    ///
    /// The caller is responsible for verifying the authority signature
    /// **before** calling this — `insert` does not re-verify.
    pub fn insert(&mut self, kind: ShardKind, shard: u32, card: GroupCard) -> bool {
        let key = (kind, shard);
        let slot = self.shards.entry(key).or_default();
        let recency = self.recency.entry(key).or_default();

        // Withdrawal cards evict immediately regardless of prior state.
        if card.withdrawn {
            slot.remove(&card.group_id);
            recency.retain(|g| g != &card.group_id);
            return true; // always accept withdrawal
        }

        // Compare revisions.
        if let Some(existing) = slot.get(&card.group_id) {
            if !card.supersedes(existing) && card.revision <= existing.revision {
                return false;
            }
        }

        slot.insert(card.group_id.clone(), card.clone());
        recency.retain(|g| g != &card.group_id);
        recency.push(card.group_id.clone());

        // LRU eviction on overflow.
        while recency.len() > self.capacity {
            if let Some(oldest) = recency.drain(..1).next() {
                slot.remove(&oldest);
            }
        }
        true
    }

    /// Insert a card received from another node.
    ///
    /// Like [`Self::insert`], but a live cached card for the same group, in
    /// any shard, is replaced or withdrawn only by its own authority (see
    /// [`GroupCard::replacement_verdict`]). Cards that expired before
    /// `now_ms` do not count. Returns `Ok(true)` when the card was stored or
    /// the withdrawal applied, `Ok(false)` when it was stale, and `Err` when
    /// it was refused. The caller verifies the signature first.
    pub fn insert_checked(
        &mut self,
        kind: ShardKind,
        shard: u32,
        card: GroupCard,
        roster_admins: &BTreeSet<String>,
        now_ms: u64,
    ) -> Result<bool, CardRefusal> {
        let verdict_for = |cached: Option<&GroupCard>| {
            if card.withdrawn {
                card.withdrawal_verdict(cached, roster_admins)
            } else {
                card.replacement_verdict(cached, roster_admins)
            }
        };
        let mut live = self
            .shards
            .values()
            .filter_map(|slot| slot.get(&card.group_id))
            .filter(|cached| cached.expiry_millis() >= now_ms)
            .peekable();
        if live.peek().is_none() {
            if let CardReplacement::Refused(refusal) = verdict_for(None) {
                return Err(refusal);
            }
        }
        for cached in live {
            if let CardReplacement::Refused(refusal) = verdict_for(Some(cached)) {
                return Err(refusal);
            }
        }

        let key = (kind, shard);
        let same_shard = self
            .shards
            .get(&key)
            .and_then(|slot| slot.get(&card.group_id));
        if let Some(cached) = same_shard {
            let expired = cached.expiry_millis() < now_ms;
            match verdict_for(Some(cached)) {
                _ if expired => self.remove(kind, shard, &card.group_id),
                CardReplacement::Replace => {
                    if !card.withdrawn {
                        // An authority may replace a card that is not
                        // older than its own; plain `insert` keeps only
                        // revision order, so clear the slot first.
                        self.remove(kind, shard, &card.group_id);
                    }
                }
                CardReplacement::Stale => return Ok(false),
                CardReplacement::Refused(refusal) => return Err(refusal),
            }
        }
        Ok(self.insert(kind, shard, card))
    }

    /// Look up a card by `group_id` across all subscribed shards.
    #[must_use]
    pub fn get(&self, group_id: &str) -> Option<&GroupCard> {
        for slot in self.shards.values() {
            if let Some(card) = slot.get(group_id) {
                return Some(card);
            }
        }
        None
    }

    /// Remove a group from a specific shard. Idempotent.
    pub fn remove(&mut self, kind: ShardKind, shard: u32, group_id: &str) {
        let key = (kind, shard);
        if let Some(slot) = self.shards.get_mut(&key) {
            slot.remove(group_id);
        }
        if let Some(recency) = self.recency.get_mut(&key) {
            recency.retain(|g| g != group_id);
        }
    }

    /// Get all cards in a specific shard.
    #[must_use]
    pub fn shard_cards(&self, kind: ShardKind, shard: u32) -> Vec<GroupCard> {
        self.shards
            .get(&(kind, shard))
            .map(|s| s.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Build a digest of a shard's current state.
    #[must_use]
    pub fn shard_digest(&self, kind: ShardKind, shard: u32) -> Vec<DigestEntry> {
        self.shards
            .get(&(kind, shard))
            .map(|s| s.values().map(DigestEntry::from_card).collect())
            .unwrap_or_default()
    }

    /// Given a peer's digest, return the `group_id`s we should pull
    /// (peer has newer revision than us, or we don't have it at all).
    #[must_use]
    pub fn pull_targets(
        &self,
        kind: ShardKind,
        shard: u32,
        peer_digest: &[DigestEntry],
    ) -> Vec<String> {
        let slot = self.shards.get(&(kind, shard));
        peer_digest
            .iter()
            .filter(|entry| match slot.and_then(|s| s.get(&entry.group_id)) {
                Some(local) => entry.revision > local.revision,
                None => true,
            })
            .map(|e| e.group_id.clone())
            .collect()
    }

    /// Total number of cached cards across all shards (deduped by
    /// group_id across shards).
    #[must_use]
    pub fn total_unique_groups(&self) -> usize {
        let mut seen = std::collections::HashSet::new();
        for slot in self.shards.values() {
            for id in slot.keys() {
                seen.insert(id.clone());
            }
        }
        seen.len()
    }

    /// Iterate over all cached cards across all shards. Duplicates may
    /// be emitted if the same group lives in multiple shards (tag +
    /// name + id all hit).
    pub fn iter_all(&self) -> impl Iterator<Item = &GroupCard> {
        self.shards.values().flat_map(|s| s.values())
    }

    /// Full-text-ish search by tag or name substring across ALL cached
    /// shards. Case-insensitive. Returns a deduplicated (by group_id)
    /// list of cards.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<GroupCard> {
        let q = query.to_lowercase();
        let mut seen = std::collections::HashSet::<String>::new();
        let mut out = Vec::new();
        for card in self.iter_all() {
            if seen.contains(&card.group_id) {
                continue;
            }
            let name_match = card.name.to_lowercase().contains(&q);
            let tag_match = card.tags.iter().any(|t| normalize_tag(t).contains(&q));
            let id_match = card.group_id == q;
            if name_match || tag_match || id_match {
                seen.insert(card.group_id.clone());
                out.push(card.clone());
            }
        }
        out
    }
}

// ────────────────────── ListedToContacts pairwise sync ───────────────────

/// Contact-scoped digest carried over the existing direct-message
/// channel. Never published to public topics.
///
/// The sender enumerates their `ListedToContacts` groups (digest
/// entries only — no full cards in the digest itself) so the recipient
/// can pull specific groups they're missing via a second direct
/// message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListedToContactsDigest {
    pub sender_agent_id: String,
    pub issued_at: u64,
    pub entries: Vec<DigestEntry>,
}

/// Pull request — recipient asks the sender for specific group_ids
/// they saw in a prior [`ListedToContactsDigest`] but don't yet hold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListedToContactsPull {
    pub requester_agent_id: String,
    pub issued_at: u64,
    pub group_ids: Vec<String>,
}

/// A pulled card envelope — response to a [`ListedToContactsPull`].
/// Carries a full signed [`GroupCard`] over the direct channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListedToContactsCard {
    pub sender_agent_id: String,
    pub issued_at: u64,
    pub card: Box<GroupCard>,
}

// ────────────────────── Subscription persistence ────────────────────────

/// One subscribed shard. Persisted to disk so the daemon re-subscribes
/// across restarts with staggered jitter (see
/// `DEFAULT_RESUBSCRIBE_JITTER_SECS` in the daemon).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubscriptionRecord {
    pub kind: ShardKind,
    pub shard: u32,
    /// Optional human-readable key (tag / word / group_id) that produced
    /// this subscription. Debug aid only — not authoritative.
    #[serde(default)]
    pub key: Option<String>,
    /// Unix milliseconds the subscription was added.
    pub subscribed_at: u64,
}

/// Serialisable subscription set. Persisted as
/// `~/.x0x/directory-subscriptions.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubscriptionSet {
    pub subscriptions: Vec<SubscriptionRecord>,
}

impl SubscriptionSet {
    /// Insert or refresh a subscription record. Returns `true` if it was
    /// newly added, `false` if it already existed (subscribed_at kept
    /// at the earlier value).
    pub fn add(&mut self, rec: SubscriptionRecord) -> bool {
        for existing in &self.subscriptions {
            if existing.kind == rec.kind && existing.shard == rec.shard {
                return false;
            }
        }
        self.subscriptions.push(rec);
        true
    }

    /// Remove a subscription. Returns `true` if it existed.
    pub fn remove(&mut self, kind: ShardKind, shard: u32) -> bool {
        let before = self.subscriptions.len();
        self.subscriptions
            .retain(|s| !(s.kind == kind && s.shard == shard));
        self.subscriptions.len() != before
    }

    /// Check containment.
    #[must_use]
    pub fn contains(&self, kind: ShardKind, shard: u32) -> bool {
        self.subscriptions
            .iter()
            .any(|s| s.kind == kind && s.shard == shard)
    }

    /// Count of subscriptions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.subscriptions.len()
    }

    /// Is the set empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.subscriptions.is_empty()
    }
}

// ─────────────────────────────── Tests ──────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::policy::{
        GroupAdmission, GroupConfidentiality, GroupDiscoverability, GroupPolicySummary,
        GroupReadAccess, GroupWriteAccess,
    };

    fn make_card(group_id: &str, revision: u64, withdrawn: bool) -> GroupCard {
        GroupCard {
            group_id: group_id.to_string(),
            name: "Test".into(),
            description: "".into(),
            avatar_url: None,
            banner_url: None,
            tags: vec!["rust".into()],
            policy_summary: GroupPolicySummary {
                discoverability: GroupDiscoverability::PublicDirectory,
                admission: GroupAdmission::RequestAccess,
                confidentiality: GroupConfidentiality::MlsEncrypted,
                read_access: GroupReadAccess::MembersOnly,
                write_access: GroupWriteAccess::MembersOnly,
            },
            owner_agent_id: "ff".repeat(32),
            admin_count: 1,
            member_count: 2,
            created_at: 0,
            updated_at: 0,
            request_access_enabled: true,
            metadata_topic: None,
            revision,
            state_hash: format!("h{revision}"),
            prev_state_hash: None,
            issued_at: 1_000 + revision,
            expires_at: 100_000,
            authority_agent_id: String::new(),
            authority_public_key: String::new(),
            withdrawn,
            signature: String::new(),
        }
    }

    #[test]
    fn shard_of_is_deterministic() {
        let a = shard_of(ShardKind::Tag, "ai");
        let b = shard_of(ShardKind::Tag, "ai");
        assert_eq!(a, b);
        assert!(a < SHARD_COUNT);
    }

    #[test]
    fn shard_of_differs_per_kind() {
        let t = shard_of(ShardKind::Tag, "ai");
        let n = shard_of(ShardKind::Name, "ai");
        let i = shard_of(ShardKind::Id, "ai");
        // With BLAKE3 these should almost certainly differ.
        assert!(t != n || n != i);
    }

    #[test]
    fn topic_format() {
        assert_eq!(topic_for(ShardKind::Tag, 42), "x0x.directory.tag.42");
        assert_eq!(topic_for(ShardKind::Name, 0), "x0x.directory.name.0");
        assert_eq!(topic_for(ShardKind::Id, 65_535), "x0x.directory.id.65535");
    }

    #[test]
    fn normalize_tag_strips_case_and_whitespace() {
        assert_eq!(normalize_tag("  AI  "), "ai");
        assert_eq!(normalize_tag("Rust"), "rust");
    }

    #[test]
    fn name_words_splits_lowers_dedupes_filters() {
        let w = name_words("Rust Async Runtime RUST");
        assert_eq!(w, vec!["async", "runtime", "rust"]);
    }

    #[test]
    fn name_words_caps_at_limit() {
        let long = "a1 b2 c3 d4 e5 f6 g7 h8 i9 j10";
        let w = name_words(long);
        assert!(w.len() <= MAX_NAME_WORDS);
    }

    #[test]
    fn shards_for_public_includes_all_kinds() {
        let shards = shards_for_public(&["ai".into(), "rust".into()], "Async Runtime", "abc123");
        let kinds: std::collections::HashSet<_> = shards.iter().map(|(k, _, _)| *k).collect();
        assert!(kinds.contains(&ShardKind::Tag));
        assert!(kinds.contains(&ShardKind::Name));
        assert!(kinds.contains(&ShardKind::Id));
    }

    #[test]
    fn shards_for_public_caps_tags() {
        let many_tags: Vec<String> = (0..100).map(|i| format!("tag{i}")).collect();
        let shards = shards_for_public(&many_tags, "Test", "g1");
        let tag_count = shards
            .iter()
            .filter(|(k, _, _)| *k == ShardKind::Tag)
            .count();
        assert!(tag_count <= MAX_TAGS_PER_GROUP);
    }

    #[test]
    fn shards_for_public_dedups_tags() {
        let shards = shards_for_public(&["ai".into(), "AI".into(), "ai".into()], "t", "g1");
        let tag_count = shards
            .iter()
            .filter(|(k, _, _)| *k == ShardKind::Tag)
            .count();
        assert_eq!(tag_count, 1);
    }

    #[test]
    fn shards_for_public_includes_exactly_one_id() {
        let shards = shards_for_public(&["ai".into()], "t", "g1");
        let id_count = shards
            .iter()
            .filter(|(k, _, _)| *k == ShardKind::Id)
            .count();
        assert_eq!(id_count, 1);
    }

    #[test]
    fn privacy_rules_gate_public_shards() {
        assert!(may_publish_to_public_shards(
            GroupDiscoverability::PublicDirectory
        ));
        assert!(!may_publish_to_public_shards(
            GroupDiscoverability::ListedToContacts
        ));
        assert!(!may_publish_to_public_shards(GroupDiscoverability::Hidden));
    }

    #[test]
    fn cache_keeps_highest_revision() {
        let mut cache = DirectoryShardCache::default();
        assert!(cache.insert(ShardKind::Tag, 1, make_card("g1", 1, false)));
        assert!(cache.insert(ShardKind::Tag, 1, make_card("g1", 2, false)));
        assert!(!cache.insert(ShardKind::Tag, 1, make_card("g1", 1, false)));
        let got = cache.get("g1").unwrap();
        assert_eq!(got.revision, 2);
    }

    #[test]
    fn cache_evicts_on_withdrawal() {
        let mut cache = DirectoryShardCache::default();
        cache.insert(ShardKind::Tag, 1, make_card("g1", 5, false));
        assert!(cache.get("g1").is_some());
        cache.insert(ShardKind::Tag, 1, make_card("g1", 6, true));
        assert!(cache.get("g1").is_none());
    }

    #[test]
    fn cache_lru_evicts_oldest() {
        let mut cache = DirectoryShardCache::new(3);
        for i in 0..5 {
            cache.insert(ShardKind::Tag, 1, make_card(&format!("g{i}"), 1, false));
        }
        // After inserting 5 with capacity 3, only the last 3 (g2, g3, g4) remain.
        assert!(cache.get("g0").is_none());
        assert!(cache.get("g1").is_none());
        assert!(cache.get("g2").is_some());
        assert!(cache.get("g3").is_some());
        assert!(cache.get("g4").is_some());
    }

    #[test]
    fn cache_search_by_tag_and_name() {
        let mut cache = DirectoryShardCache::default();
        let mut c1 = make_card("g1", 1, false);
        c1.name = "Rust Async".into();
        c1.tags = vec!["rust".into(), "async".into()];
        let mut c2 = make_card("g2", 1, false);
        c2.name = "Python ML".into();
        c2.tags = vec!["python".into(), "ml".into()];
        cache.insert(ShardKind::Tag, 1, c1);
        cache.insert(ShardKind::Tag, 2, c2);

        assert_eq!(cache.search("rust").len(), 1);
        assert_eq!(cache.search("ml").len(), 1);
        assert_eq!(cache.search("python").len(), 1);
        assert_eq!(cache.search("async").len(), 1);
        assert_eq!(cache.search("nomatch").len(), 0);
    }

    #[test]
    fn shard_digest_is_deterministic_and_sorted() {
        let mut cache = DirectoryShardCache::default();
        for id in ["gC", "gA", "gB"] {
            cache.insert(ShardKind::Tag, 7, make_card(id, 1, false));
        }
        let d = cache.shard_digest(ShardKind::Tag, 7);
        let ids: Vec<&str> = d.iter().map(|e| e.group_id.as_str()).collect();
        // BTreeMap preserves key order.
        assert_eq!(ids, vec!["gA", "gB", "gC"]);
    }

    #[test]
    fn pull_targets_identifies_missing_and_stale() {
        let mut cache = DirectoryShardCache::default();
        cache.insert(ShardKind::Tag, 1, make_card("g1", 5, false));
        cache.insert(ShardKind::Tag, 1, make_card("g2", 3, false));

        let peer = vec![
            DigestEntry {
                group_id: "g1".into(), // same revision — skip
                revision: 5,
                state_hash: "h5".into(),
                expires_at: 100_000,
            },
            DigestEntry {
                group_id: "g2".into(), // peer has newer — pull
                revision: 7,
                state_hash: "h7".into(),
                expires_at: 100_000,
            },
            DigestEntry {
                group_id: "g3".into(), // unknown locally — pull
                revision: 1,
                state_hash: "h1".into(),
                expires_at: 100_000,
            },
        ];
        let pulls = cache.pull_targets(ShardKind::Tag, 1, &peer);
        assert_eq!(pulls.len(), 2);
        assert!(pulls.contains(&"g2".to_string()));
        assert!(pulls.contains(&"g3".to_string()));
    }

    #[test]
    fn directory_message_roundtrip() {
        let card = Box::new(make_card("g1", 1, false));
        let msg = DirectoryMessage::Card { card };
        let bytes = msg.encode();
        let parsed = DirectoryMessage::decode(&bytes).unwrap();
        matches!(parsed, DirectoryMessage::Card { .. });
    }

    #[test]
    fn subscription_set_add_remove_contains() {
        let mut s = SubscriptionSet::default();
        let rec = SubscriptionRecord {
            kind: ShardKind::Tag,
            shard: 42,
            key: Some("ai".into()),
            subscribed_at: 1_000,
        };
        assert!(s.add(rec.clone()));
        assert!(!s.add(rec.clone())); // idempotent
        assert!(s.contains(ShardKind::Tag, 42));
        assert_eq!(s.len(), 1);
        assert!(s.remove(ShardKind::Tag, 42));
        assert!(!s.contains(ShardKind::Tag, 42));
        assert!(s.is_empty());
    }

    #[test]
    fn digest_entry_from_card() {
        let c = make_card("g1", 3, false);
        let e = DigestEntry::from_card(&c);
        assert_eq!(e.group_id, "g1");
        assert_eq!(e.revision, 3);
        assert_eq!(e.state_hash, "h3");
    }
}
