//! # L3 fetch-on-miss: announce blob cache + targeted fetch protocol.
//!
//! The V3 identity announce carries a BLAKE3 digest of the full V2
//! `IdentityAnnouncement` instead of the inline cert chain + capability
//! blob. A receiver that recognizes the digest uses its cached copy; a miss
//! triggers a targeted fetch. This module owns the cache and the fetch.
//!
//! SECURITY INVARIANT: **verify-before-cache**. A fetched blob is only
//! cached after (a) full `IdentityAnnouncement::verify()` passes AND
//! (b) `blake3(bincode(&announcement))` matches the requested digest.
//! An unverified or digest-mismatched blob is NEVER cached — this closes
//! the spoofing window where a forged announce could poison the cache.
//!
//! Disk persistence: bincode file under the daemon data dir, loaded at
//! startup, saved on insert. Bounded at [`BLOB_CACHE_MAX_ENTRIES`] (LRU).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::gossip::PubSubManager;
use crate::{identity, IdentityAnnouncement};

/// Maximum in-memory + on-disk cache entries. The fleet has ~50 active
/// agents; 256 gives 5× headroom without unbounded growth.
pub(crate) const BLOB_CACHE_MAX_ENTRIES: usize = 256;

/// Domain prefix for the announce-blob targeted request, riding the same
/// warm-targeted-request pattern as the capability service
/// (`dm_capability_service.rs:26`). Lets the request ride the steady
/// announce topic without a pre-L3 subscriber mistaking it for an announce.
/// Phase-2 wire protocol constants — connected when the V3 receiver's
/// targeted-request handler calls `serve_request`. Kept `pub(crate)` so
/// the wiring lives in the receiver, not here.
#[allow(dead_code)]
pub(crate) const ANNOUNCE_BLOB_REQUEST_DOMAIN: &[u8] = b"x0x/announce/v3/blob-request-v1\0";

/// Dedicated topic for the blob fetch (kept separate from the announce
/// topic so a Leaf that unsubscribes from announces still serves fetches).
#[allow(dead_code)]
pub(crate) const ANNOUNCE_BLOB_TOPIC: &str = "x0x/announce/v3/blob";

/// A cached full V2 announcement, keyed by its BLAKE3 digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedBlob {
    /// BLAKE3-256 of the bincode-serialized `IdentityAnnouncement`.
    pub digest: [u8; 32],
    /// Monotonic version from the V3 announce (bumped on payload change).
    pub payload_version: u64,
    /// The full, verified V2 `IdentityAnnouncement`.
    pub full: IdentityAnnouncement,
    /// Unix seconds when this blob was fetched/cached.
    pub fetched_at_unix: u64,
}

/// Targeted request for a specific announce blob by digest.
#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct AnnounceBlobRequest {
    pub protocol_version: u16,
    /// The BLAKE3 digest of the blob the requester wants.
    pub digest: [u8; 32],
    /// The requesting agent — for logging only; the response carries
    /// self-authenticating data (the blob is independently signed).
    pub requester_agent_id: [u8; 32],
}

/// Response carrying the full V2 announcement bytes.
#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct AnnounceBlobResponse {
    pub protocol_version: u16,
    /// Bincode-serialized `IdentityAnnouncement` (V2).
    pub announcement_bytes: Vec<u8>,
}

/// Metering counters surfaced via [`AnnounceBlobCache::snapshot`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct AnnounceBlobCacheStats {
    pub blob_cache_hits: u64,
    pub blob_cache_misses: u64,
    pub blob_fetches_ok: u64,
    pub blob_fetches_failed: u64,
}

/// Internal LRU bookkeeping — access order for eviction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LruEntry {
    digest: [u8; 32],
    access_counter: u64,
}

/// The blob cache: in-memory `HashMap` + optional disk persistence.
pub struct AnnounceBlobCache {
    blobs: tokio::sync::RwLock<HashMap<[u8; 32], Arc<CachedBlob>>>,
    lru: tokio::sync::RwLock<Vec<LruEntry>>,
    access_counter: AtomicU64,
    disk_path: Option<PathBuf>,
    stats_hits: AtomicU64,
    stats_misses: AtomicU64,
    stats_fetches_ok: AtomicU64,
    stats_fetches_failed: AtomicU64,
}

impl AnnounceBlobCache {
    /// Create a cache with optional disk persistence at `disk_path`.
    pub fn new(disk_path: Option<PathBuf>) -> Self {
        let cache = Self {
            blobs: tokio::sync::RwLock::new(HashMap::new()),
            lru: tokio::sync::RwLock::new(Vec::new()),
            access_counter: AtomicU64::new(0),
            disk_path,
            stats_hits: AtomicU64::new(0),
            stats_misses: AtomicU64::new(0),
            stats_fetches_ok: AtomicU64::new(0),
            stats_fetches_failed: AtomicU64::new(0),
        };
        cache.load_from_disk();
        cache
    }

    /// Look up a cached blob by digest. Returns `None` on miss.
    /// Updates LRU access order on hit.
    pub async fn get(&self, digest: &[u8; 32]) -> Option<Arc<CachedBlob>> {
        let hit = self.blobs.read().await.get(digest).cloned();
        if hit.is_some() {
            self.stats_hits.fetch_add(1, Ordering::Relaxed);
            self.touch_lru(digest).await;
        } else {
            self.stats_misses.fetch_add(1, Ordering::Relaxed);
        }
        hit
    }

    /// Insert a blob after verification. The caller is responsible for
    /// having run `verify()` + digest check BEFORE calling this — this
    /// method trusts the caller (the public `ensure_blob` enforces it).
    pub(crate) async fn insert_verified(&self, blob: CachedBlob) {
        let digest = blob.digest;
        let blob = Arc::new(blob);
        {
            let mut blobs = self.blobs.write().await;
            blobs.insert(digest, Arc::clone(&blob));
            // LRU: if over cap, evict the least-recently-used entry.
            if blobs.len() > BLOB_CACHE_MAX_ENTRIES {
                let mut lru = self.lru.write().await;
                lru.retain(|entry| blobs.contains_key(&entry.digest));
                lru.sort_by_key(|entry| entry.access_counter);
                while blobs.len() > BLOB_CACHE_MAX_ENTRIES && !lru.is_empty() {
                    let evicted = lru.remove(0);
                    blobs.remove(&evicted.digest);
                }
            }
        }
        self.touch_lru(&digest).await;
        self.save_to_disk().await;
    }

    /// The public entry point Claude's V3 receiver calls.
    ///
    /// Returns the cached blob immediately on hit. On miss, spawns a
    /// background fetch (non-blocking — returns `None`); the next
    /// heartbeat's `ensure_blob` call will see the fetched entry.
    ///
    /// SECURITY: the fetched blob is verified (`verify()` + digest match)
    /// before caching; a failed verification increments
    /// `blob_fetches_failed` and the blob is discarded.
    #[allow(clippy::too_many_arguments)]
    pub async fn ensure_blob(
        self: &Arc<Self>,
        pubsub: &PubSubManager,
        digest: &[u8; 32],
        payload_version: u64,
        agent_id: &identity::AgentId,
        machine_id: &identity::MachineId,
    ) -> Option<Arc<CachedBlob>> {
        if let Some(hit) = self.get(digest).await {
            return Some(hit);
        }

        // Miss — spawn the fetch, return None immediately. The pubsub
        // reference cannot cross the spawn boundary ('static); the fetch
        // task goes through the cache's own handle once Claude's V3
        // receiver wires the responder side. Until then this is a
        // metered no-op: `blob_fetches_failed` increments and the next
        // heartbeat retries — never blocks the caller.
        let _ = pubsub;
        let cache = Arc::clone(self);
        let digest = *digest;
        let agent_id = *agent_id;
        let machine_id = *machine_id;
        tokio::spawn(async move {
            match fetch_and_verify(&cache, &digest, &agent_id, &machine_id).await {
                Ok(blob) => {
                    cache.stats_fetches_ok.fetch_add(1, Ordering::Relaxed);
                    cache
                        .insert_verified(CachedBlob {
                            payload_version,
                            ..blob
                        })
                        .await;
                }
                Err(reason) => {
                    cache.stats_fetches_failed.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        target: "announce.blob",
                        digest = %hex::encode(digest),
                        agent = %hex::encode(agent_id.0),
                        %reason,
                        "announce blob fetch failed — next heartbeat retries"
                    );
                }
            }
        });
        None
    }

    /// Serve a blob request from our own cache or our current announcement.
    /// Called by the targeted-request handler when a peer asks for a digest.
    pub async fn serve_request(
        &self,
        digest: &[u8; 32],
        current_announcement: Option<&IdentityAnnouncement>,
    ) -> Option<Vec<u8>> {
        // Check the cache first.
        if let Some(cached) = self.get(digest).await {
            return bincode::serialize(&cached.full).ok();
        }
        // Check if it matches our own current announcement.
        if let Some(announcement) = current_announcement {
            if let Ok(bytes) = bincode::serialize(announcement) {
                let computed = blake3::hash(&bytes);
                if computed.as_bytes() == digest {
                    return Some(bytes);
                }
            }
        }
        None
    }

    /// Snapshot the metering counters.
    pub fn snapshot(&self) -> AnnounceBlobCacheStats {
        AnnounceBlobCacheStats {
            blob_cache_hits: self.stats_hits.load(Ordering::Relaxed),
            blob_cache_misses: self.stats_misses.load(Ordering::Relaxed),
            blob_fetches_ok: self.stats_fetches_ok.load(Ordering::Relaxed),
            blob_fetches_failed: self.stats_fetches_failed.load(Ordering::Relaxed),
        }
    }

    /// Compute the BLAKE3 digest of a serialized announcement.
    pub fn digest_of(announcement: &IdentityAnnouncement) -> Option<[u8; 32]> {
        bincode::serialize(announcement)
            .ok()
            .map(|bytes| blake3::hash(&bytes).into())
    }

    // ── Internal ──

    async fn touch_lru(&self, digest: &[u8; 32]) {
        let counter = self.access_counter.fetch_add(1, Ordering::Relaxed);
        let mut lru = self.lru.write().await;
        // Update or insert.
        if let Some(entry) = lru.iter_mut().find(|e| e.digest == *digest) {
            entry.access_counter = counter;
        } else {
            lru.push(LruEntry {
                digest: *digest,
                access_counter: counter,
            });
        }
    }

    fn load_from_disk(&self) {
        let Some(path) = &self.disk_path else { return };
        let Ok(bytes) = std::fs::read(path) else {
            tracing::debug!(
                path = %path.display(),
                "announce blob cache: no disk file (first run)"
            );
            return;
        };
        match bincode::deserialize::<Vec<CachedBlob>>(&bytes) {
            Ok(blobs) => {
                // Use blocking lock at startup (before the runtime spawns tasks).
                if let Ok(mut map) = self.blobs.try_write() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    for blob in blobs.into_iter().take(BLOB_CACHE_MAX_ENTRIES) {
                        map.insert(
                            blob.digest,
                            Arc::new(CachedBlob {
                                fetched_at_unix: blob.fetched_at_unix.min(now),
                                ..blob
                            }),
                        );
                    }
                    tracing::info!(
                        path = %path.display(),
                        entries = map.len(),
                        "announce blob cache: loaded from disk"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "announce blob cache: disk file corrupt — starting empty"
                );
            }
        }
    }

    async fn save_to_disk(&self) {
        let Some(path) = &self.disk_path else { return };
        let blobs: Vec<CachedBlob> = {
            let map = self.blobs.read().await;
            map.values().map(|b| (**b).clone()).collect()
        };
        match bincode::serialize(&blobs) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(path, &bytes) {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "announce blob cache: disk save failed"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "announce blob cache: serialization for disk failed"
                );
            }
        }
    }
}

/// Fetch a blob via targeted request and verify before returning.
/// SECURITY: the fetched blob MUST pass `verify()` and the digest MUST
/// match — this is the verify-before-cache invariant.
async fn fetch_and_verify(
    cache: &AnnounceBlobCache,
    digest: &[u8; 32],
    agent_id: &identity::AgentId,
    machine_id: &identity::MachineId,
) -> Result<CachedBlob, String> {
    // Phase 2 (Claude's receiver wiring) publishes an `AnnounceBlobRequest`
    // over the warm-targeted-request domain and awaits the response; the
    // verify_fetched_blob gate below is what makes any fetched bytes safe.
    // Phase 1: no responder exists yet, so the miss is metered and retried.
    tracing::debug!(
        target: "announce.blob",
        digest = %hex::encode(digest),
        agent = %hex::encode(agent_id.as_bytes()),
        machine = %machine_id.as_bytes().iter().map(|b| format!("{b:02x}")).take(8).collect::<String>(),
        cached = cache.snapshot().blob_cache_hits,
        "announce blob fetch deferred (responder pending)"
    );
    Err("announce blob fetch: responder protocol pending V3 receiver wiring".to_string())
}

/// Verify a fetched blob against the expected digest.
/// This is the SECURITY GATE — called before any cache insert.
///
/// Returns `Ok(CachedBlob)` on success; `Err(reason)` on any failure.
pub fn verify_fetched_blob(
    announcement_bytes: &[u8],
    expected_digest: &[u8; 32],
    payload_version: u64,
) -> Result<CachedBlob, String> {
    // Step 1: compute the digest and check it matches.
    let computed = blake3::hash(announcement_bytes);
    if computed.as_bytes() != expected_digest {
        return Err(format!(
            "digest mismatch: expected {}, got {}",
            hex::encode(expected_digest),
            hex::encode(computed.as_bytes())
        ));
    }

    // Step 2: deserialize into an IdentityAnnouncement.
    let announcement: IdentityAnnouncement = bincode::deserialize(announcement_bytes)
        .map_err(|e| format!("deserialization failed: {e}"))?;

    // Step 3: full cryptographic verification (machine_id ↔ pubkey binding
    // + ML-DSA signature over the unsigned canonical bytes).
    announcement
        .verify()
        .map_err(|e| format!("announcement verification failed: {e}"))?;

    // Verified — safe to cache.
    Ok(CachedBlob {
        digest: *expected_digest,
        payload_version,
        full: announcement,
        fetched_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    })
}

/// Encode a targeted blob request for the wire (domain-prefixed).
#[allow(dead_code)]
pub(crate) fn encode_blob_request(
    digest: &[u8; 32],
    requester_agent_id: &identity::AgentId,
) -> Vec<u8> {
    let request = AnnounceBlobRequest {
        protocol_version: 1,
        digest: *digest,
        requester_agent_id: requester_agent_id.0,
    };
    let encoded = bincode::serialize(&request).unwrap_or_default();
    let mut wire = Vec::with_capacity(ANNOUNCE_BLOB_REQUEST_DOMAIN.len() + encoded.len());
    wire.extend_from_slice(ANNOUNCE_BLOB_REQUEST_DOMAIN);
    wire.extend_from_slice(&encoded);
    wire
}

/// Decode a domain-prefixed blob request from the wire.
#[allow(dead_code)]
pub(crate) fn decode_blob_request(wire: &[u8]) -> Option<AnnounceBlobRequest> {
    let encoded = wire.strip_prefix(ANNOUNCE_BLOB_REQUEST_DOMAIN)?;
    bincode::deserialize(encoded).ok()
}

/// Encode a blob response for the wire.
#[allow(dead_code)]
pub(crate) fn encode_blob_response(announcement_bytes: Vec<u8>) -> Vec<u8> {
    let response = AnnounceBlobResponse {
        protocol_version: 1,
        announcement_bytes,
    };
    bincode::serialize(&response).unwrap_or_default()
}

/// Decode a blob response from the wire.
#[allow(dead_code)]
pub(crate) fn decode_blob_response(wire: &[u8]) -> Option<AnnounceBlobResponse> {
    bincode::deserialize(wire).ok()
}

// ---------------------------------------------------------------------------
// Tests — EXTEND this module, never replace pre-existing tests.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentKeypair;

    /// Build a signed, verifiable IdentityAnnouncement for testing.
    fn test_announcement() -> (IdentityAnnouncement, AgentKeypair) {
        let agent_kp = AgentKeypair::generate().expect("agent keypair");
        let machine_kp = crate::identity::MachineKeypair::generate().expect("machine keypair");
        let agent_id = agent_kp.agent_id();
        let machine_id = machine_kp.machine_id();

        // Use the existing announce builder path — produces a valid,
        // signed announcement.
        let announcement = IdentityAnnouncement {
            agent_id,
            machine_id,
            user_id: None,
            agent_certificate: None,
            machine_public_key: machine_kp.public_key().as_bytes().to_vec(),
            machine_signature: Vec::new(), // filled below
            addresses: vec!["127.0.0.1:5483".parse().expect("addr")],
            announced_at: 1_800_000_000,
            nat_type: Some("FullCone".to_string()),
            can_receive_direct: Some(true),
            is_relay: Some(false),
            is_coordinator: Some(false),
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
            agent_public_key: agent_kp.public_key().as_bytes().to_vec(),
        };

        // Sign the unsigned canonical bytes.
        let unsigned = announcement.to_unsigned();
        let unsigned_bytes =
            bincode::serialize(&unsigned).expect("serialize unsigned announcement");
        let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            machine_kp.secret_key(),
            &unsigned_bytes,
        )
        .expect("sign announcement");

        (
            IdentityAnnouncement {
                machine_signature: signature.as_bytes().to_vec(),
                ..announcement
            },
            agent_kp,
        )
    }

    /// Disk round-trip: what goes in comes back out after a reload.
    #[tokio::test]
    async fn blob_cache_disk_round_trip() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("announce-blobs.bin");
        let (announcement, _) = test_announcement();
        let digest = AnnounceBlobCache::digest_of(&announcement).expect("digest");

        {
            let cache = AnnounceBlobCache::new(Some(path.clone()));
            cache
                .insert_verified(CachedBlob {
                    digest,
                    payload_version: 1,
                    full: announcement.clone(),
                    fetched_at_unix: 1_800_000_000,
                })
                .await;
        }

        // New cache instance loads from disk.
        let reloaded = AnnounceBlobCache::new(Some(path));
        let hit = reloaded.get(&digest).await;
        assert!(hit.is_some(), "blob must survive disk round-trip");
        assert_eq!(hit.unwrap().full.agent_id, announcement.agent_id);
    }

    /// SECURITY: verify-before-cache — a forged blob (invalid signature)
    /// is rejected by `verify_fetched_blob` and never cached.
    #[tokio::test]
    async fn verify_before_cache_rejects_forged_blob() {
        let (mut announcement, _) = test_announcement();
        // Corrupt the signature — the announcement will fail verify().
        announcement.machine_signature = vec![0u8; 32];
        let bytes = bincode::serialize(&announcement).expect("serialize");
        let digest = blake3::hash(&bytes).into();

        let result = verify_fetched_blob(&bytes, &digest, 1);
        assert!(
            result.is_err(),
            "a forged announcement must be rejected before caching"
        );
        assert!(
            result.unwrap_err().contains("verification failed"),
            "the error should name the verification failure"
        );
    }

    /// SECURITY: digest mismatch — the fetched bytes don't hash to the
    /// requested digest, so the blob is rejected even if well-formed.
    #[tokio::test]
    async fn digest_mismatch_rejected() {
        let (announcement, _) = test_announcement();
        let bytes = bincode::serialize(&announcement).expect("serialize");
        let wrong_digest: [u8; 32] = [0xAB; 32]; // deliberately wrong

        let result = verify_fetched_blob(&bytes, &wrong_digest, 1);
        assert!(result.is_err(), "digest mismatch must be rejected");
        assert!(
            result.unwrap_err().contains("digest mismatch"),
            "the error should name the digest mismatch"
        );
    }

    /// LRU cap: inserting more than BLOB_CACHE_MAX_ENTRIES evicts the
    /// least-recently-used entry.
    #[tokio::test]
    async fn lru_cap_evicts_least_recently_used() {
        let cache = AnnounceBlobCache::new(None); // no disk

        // Fill to cap + 1. Digests are BLAKE3 of the index — distinct even
        // past u8 wraparound (a naive `[i as u8; 32]` collides at i=256).
        // One announcement shared across entries: the payload is opaque to
        // the LRU logic and keygen is the expensive part.
        let shared = test_announcement().0;
        for i in 0..=BLOB_CACHE_MAX_ENTRIES {
            let digest: [u8; 32] = blake3::hash(&i.to_le_bytes()).into();
            let blob = CachedBlob {
                digest,
                payload_version: 1,
                full: shared.clone(),
                fetched_at_unix: 1_800_000_000,
            };
            cache.insert_verified(blob).await;
        }

        // The first entry should have been evicted (LRU).
        let first: [u8; 32] = blake3::hash(&0u64.to_le_bytes()).into();
        assert!(
            cache.get(&first).await.is_none(),
            "the least-recently-used entry must be evicted at cap"
        );

        // The last entry should still be present.
        let last: [u8; 32] = blake3::hash(&(BLOB_CACHE_MAX_ENTRIES as u64).to_le_bytes()).into();
        assert!(
            cache.get(&last).await.is_some(),
            "the most-recently-used entry must survive"
        );
    }

    /// Digest computation is deterministic: the same announcement produces
    /// the same digest.
    #[tokio::test]
    async fn digest_computation_is_deterministic() {
        let (announcement, _) = test_announcement();
        let d1 = AnnounceBlobCache::digest_of(&announcement);
        let d2 = AnnounceBlobCache::digest_of(&announcement);
        assert_eq!(d1, d2, "same announcement must produce the same digest");
        assert!(d1.is_some());
    }
}
