//! # L3 fetch-on-miss: announce blob cache + targeted fetch protocol.
//!
//! The V3 identity announce carries a BLAKE3 digest of the inline
//! `(user_id, agent_certificate)` pair instead of the pair itself — see
//! [`crate::announce_v3::cert_digest`]. A receiver that recognizes the
//! digest uses its cached copy; a miss triggers a targeted fetch. This
//! module owns the cache and the fetch.
//!
//! THE BLOB IS THE PAIR, not the full V2 announcement: the digest is
//! defined over `bincode(&(Option<UserId>, Option<AgentCertificate>))`,
//! which is stable across heartbeats (announced_at never enters it).
//! Fetching the full announcement would churn the digest every beat.
//!
//! SECURITY INVARIANT: **verify-before-cache**. A fetched blob is only
//! cached after (a) `blake3(blob_bytes)` matches the requested digest,
//! (b) the pair deserializes, and (c) the pair passes the same pairing
//! rule `IdentityAnnouncement::verify` enforces: `(Some, Some)` requires
//! `cert.verify()` AND `cert.agent_id() == expected_agent_id` AND
//! `cert.user_id() == user_id`; `(None, None)` is anonymous (ok); a
//! mixed pair is rejected. An unverified or mismatched blob is NEVER
//! cached — this closes the spoofing window into the cache.
//!
//! Disk persistence: bincode file under the daemon data dir, loaded at
//! startup, saved on insert. Bounded at `BLOB_CACHE_MAX_ENTRIES` (LRU).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::gossip::PubSubManager;
use crate::identity;

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

/// Domain prefix for blob responses on `ANNOUNCE_BLOB_TOPIC` — lets the
/// fetcher distinguish a response from a concurrent request (both ride the
/// same topic).
pub(crate) const ANNOUNCE_BLOB_RESPONSE_DOMAIN: &[u8] = b"x0x/announce/v3/blob-response-v1\0";

/// How long a fetcher waits for a response before giving up (the next
/// heartbeat retries). Generous for a mesh round-trip, short enough that a
/// silent responder does not pin tasks.
pub(crate) const BLOB_FETCH_TIMEOUT_SECS: u64 = 5;

/// A verified requester can make peers serve blobs, but must not be able to
/// amplify traffic without bound. Mirrors the caps responder's coalescing
/// window (`dm_capability_service.rs`). Tracked PER DIGEST (#656): one
/// global instant starved every unrelated blob whenever a single digest was
/// busy — a dropped request was silently discarded, retrying only after the
/// fetcher's 5 s deadline.
const MIN_RESPONSE_INTERVAL_SECS: u64 = 1;

/// The window map is deliberately unbounded: owner-only serving means a
/// responder's keys grow only when its OWN pair rotates (each rotation
/// adds one ~40-byte entry), never from peer traffic — an attacker cannot
/// add keys. The prior 256-entry eviction cap was unreachable in practice
/// and was dropped (#656 round 2).
///
/// The serving daemon's current `(user_id, agent_certificate)` pair, shared
/// with the responder task so consent changes are picked up live.
pub type SharedCertPair =
    Arc<std::sync::RwLock<(Option<identity::UserId>, Option<identity::AgentCertificate>)>>;

/// Whether a V3 announce's cert digest warrants a fetch: anonymous
/// announces (the `(None, None)` constant) never do — there is nothing to
/// fetch, and every beat from an anonymous agent would otherwise fire a
/// pointless request. Single definition so the receiver arm and tests
/// agree on the rule.
#[must_use]
pub fn fetch_warranted(cert_digest: &[u8; 32]) -> bool {
    *cert_digest != crate::announce_v3::anonymous_cert_digest()
}

/// Build a [`SharedCertPair`] from an initial pair.
pub fn shared_cert_pair(
    user_id: Option<identity::UserId>,
    cert: Option<identity::AgentCertificate>,
) -> SharedCertPair {
    Arc::new(std::sync::RwLock::new((user_id, cert)))
}

/// A cached `(user_id, agent_certificate)` pair, keyed by its BLAKE3
/// digest — exactly the bytes [`crate::announce_v3::cert_digest`] commits
/// to. Stable across heartbeats; never includes `announced_at`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedBlob {
    /// BLAKE3-256 of the bincode-serialized pair.
    pub digest: [u8; 32],
    /// Monotonic version from the V3 announce (bumped on payload change).
    pub payload_version: u64,
    /// The verified `(user_id, cert)` pair the digest commits to.
    pub user_id: Option<identity::UserId>,
    pub agent_certificate: Option<identity::AgentCertificate>,
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
    #[cfg(test)]
    pub(crate) diagnostics: AnnounceBlobDiagnostics,
}

/// Independent per-agent lifetime observations, not a coherent task census.
#[cfg(test)]
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct AnnounceBlobDiagnostics {
    pub(crate) fetches_spawned: u64,
    pub(crate) terminal_both_carriers_failed: u64,
    pub(crate) terminal_deadline_elapsed: u64,
    pub(crate) terminal_subscription_closed: u64,
    pub(crate) terminal_verifier_error: u64,
    pub(crate) responses_seen: u64,
    pub(crate) responses_skipped_malformed: u64,
    pub(crate) responses_skipped_mismatched_digest: u64,
    pub(crate) verified_requests_decoded: u64,
    pub(crate) unknown_digest: u64,
    pub(crate) pair_available: u64,
    pub(crate) coalesced_dropped: u64,
    pub(crate) response_publish_ok_local: u64,
    pub(crate) publish_failed_local: u64,
}

#[cfg(test)]
#[derive(Default)]
struct AnnounceBlobDiagnosticCounters {
    fetches_spawned: AtomicU64,
    terminal_both_carriers_failed: AtomicU64,
    terminal_deadline_elapsed: AtomicU64,
    terminal_subscription_closed: AtomicU64,
    terminal_verifier_error: AtomicU64,
    responses_seen: AtomicU64,
    responses_skipped_malformed: AtomicU64,
    responses_skipped_mismatched_digest: AtomicU64,
    verified_requests_decoded: AtomicU64,
    unknown_digest: AtomicU64,
    pair_available: AtomicU64,
    coalesced_dropped: AtomicU64,
    response_publish_ok_local: AtomicU64,
    publish_failed_local: AtomicU64,
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
    #[cfg(test)]
    diagnostics: AnnounceBlobDiagnosticCounters,
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
            #[cfg(test)]
            diagnostics: AnnounceBlobDiagnosticCounters::default(),
        };
        cache.load_from_disk();
        cache
    }

    /// #483: scan for a cached blob whose CERTIFICATE hashes to
    /// `cert_digest` (blake3(cert) — the roster-seat digest), regardless
    /// of the cache's own `(user_id, cert)` blob key. Returns the first
    /// binding whose certificate matches; the caller still applies the
    /// agent/user binding rule.
    pub async fn find_by_cert_digest(&self, cert_digest: &[u8; 32]) -> Option<Arc<CachedBlob>> {
        let blobs = self.blobs.read().await;
        blobs
            .values()
            .find(|blob| {
                blob.agent_certificate.as_ref().is_some_and(|cert| {
                    // Match owner_cert::certificate_digest_hex: bincode(cert)
                    // with a public-key fallback on serialize failure.
                    let bytes = bincode::serialize(cert)
                        .unwrap_or_else(|_| cert.agent_public_key().to_vec());
                    blake3::hash(&bytes).as_bytes() == cert_digest
                })
            })
            .cloned()
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
        pubsub: &Arc<PubSubManager>,
        digest: &[u8; 32],
        payload_version: u64,
        agent_id: &identity::AgentId,
        machine_id: &identity::MachineId,
    ) -> Option<Arc<CachedBlob>> {
        if let Some(hit) = self.get(digest).await {
            return Some(hit);
        }

        // Miss — spawn the fetch, return None immediately. `agent_id` is
        // the expected agent threaded into `verify_fetched_blob`'s cert
        // binding check. Non-blocking by contract: the next heartbeat's
        // ensure_blob sees the fetched entry (or retries the fetch).
        let cache = Arc::clone(self);
        let pubsub = Arc::clone(pubsub);
        let digest = *digest;
        let agent_id = *agent_id;
        let machine_id = *machine_id;
        #[cfg(test)]
        self.diagnostics
            .fetches_spawned
            .fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            match fetch_and_verify(&pubsub, &cache, &digest, &agent_id, &machine_id).await {
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

    /// Serve a blob request from our own current announcement state only.
    /// Called by the targeted-request handler when a peer asks for a
    /// digest. The response is the bincode of the served agent's
    /// `(user_id, agent_certificate)` pair.
    ///
    /// The ANONYMOUS digest is never served either: user keys are opt-in,
    /// so every cert-less node computes the same
    /// [`crate::announce_v3::anonymous_cert_digest`], and "exactly one
    /// owner" is impossible for a digest shared by the whole fleet. The
    /// requesting side already excludes it via [`fetch_warranted`], so no
    /// legitimate requester is affected.
    pub async fn serve_request(
        &self,
        digest: &[u8; 32],
        current_user_id: &Option<identity::UserId>,
        current_agent_certificate: &Option<identity::AgentCertificate>,
    ) -> Option<Vec<u8>> {
        if !fetch_warranted(digest) {
            return None;
        }
        if crate::announce_v3::cert_digest(current_user_id, current_agent_certificate) == *digest {
            return bincode::serialize(&(current_user_id, current_agent_certificate)).ok();
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
            #[cfg(test)]
            diagnostics: AnnounceBlobDiagnostics {
                fetches_spawned: self.diagnostics.fetches_spawned.load(Ordering::Relaxed),
                terminal_both_carriers_failed: self
                    .diagnostics
                    .terminal_both_carriers_failed
                    .load(Ordering::Relaxed),
                terminal_deadline_elapsed: self
                    .diagnostics
                    .terminal_deadline_elapsed
                    .load(Ordering::Relaxed),
                terminal_subscription_closed: self
                    .diagnostics
                    .terminal_subscription_closed
                    .load(Ordering::Relaxed),
                terminal_verifier_error: self
                    .diagnostics
                    .terminal_verifier_error
                    .load(Ordering::Relaxed),
                responses_seen: self.diagnostics.responses_seen.load(Ordering::Relaxed),
                responses_skipped_malformed: self
                    .diagnostics
                    .responses_skipped_malformed
                    .load(Ordering::Relaxed),
                responses_skipped_mismatched_digest: self
                    .diagnostics
                    .responses_skipped_mismatched_digest
                    .load(Ordering::Relaxed),
                verified_requests_decoded: self
                    .diagnostics
                    .verified_requests_decoded
                    .load(Ordering::Relaxed),
                unknown_digest: self.diagnostics.unknown_digest.load(Ordering::Relaxed),
                pair_available: self.diagnostics.pair_available.load(Ordering::Relaxed),
                coalesced_dropped: self.diagnostics.coalesced_dropped.load(Ordering::Relaxed),
                response_publish_ok_local: self
                    .diagnostics
                    .response_publish_ok_local
                    .load(Ordering::Relaxed),
                publish_failed_local: self
                    .diagnostics
                    .publish_failed_local
                    .load(Ordering::Relaxed),
            },
        }
    }

    /// Compute the digest of a `(user_id, cert)` pair — the same function
    /// the V3 announce uses. Kept here so callers don't need to import
    /// `announce_v3` for a one-liner.
    pub fn digest_of(
        user_id: &Option<identity::UserId>,
        cert: &Option<identity::AgentCertificate>,
    ) -> [u8; 32] {
        crate::announce_v3::cert_digest(user_id, cert)
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

/// Fetch a blob via the targeted/warm request routes and verify before
/// returning. SECURITY: the fetched blob MUST pass the
/// [`verify_fetched_blob`] gate — this is the verify-before-cache
/// invariant.
///
/// Routes (mirroring `publish_targeted_capability_request`):
/// - targeted: the domain-prefixed request on `ANNOUNCE_BLOB_TOPIC`;
/// - warm: the same domain-prefixed bytes on the steady identity announce
///   topic, so a responder that only watches the announce topic still
///   serves. The domain prefix keeps pre-L3 subscribers from mistaking it
///   for an announce (the X0A3/V2 decoders both reject it).
///
/// The response is matched by digest: every well-formed response carries
/// the pair whose blake3 is the requested digest, so concurrent fetchers
/// can share the topic and each picks out its own blob.
async fn fetch_and_verify(
    pubsub: &Arc<PubSubManager>,
    cache: &AnnounceBlobCache,
    digest: &[u8; 32],
    expected_agent_id: &identity::AgentId,
    machine_id: &identity::MachineId,
) -> Result<CachedBlob, String> {
    let mut responses = pubsub.subscribe(ANNOUNCE_BLOB_TOPIC.to_string()).await;

    // `encode_blob_request` returns domain-prefixed bytes; both carriers
    // publish the same prefixed payload and the responder's decoder strips
    // the domain from whichever carrier delivered it.
    let request = encode_blob_request(digest, expected_agent_id);
    let (targeted, warm) = tokio::join!(
        pubsub.publish(
            ANNOUNCE_BLOB_TOPIC.to_string(),
            Bytes::from(request.clone())
        ),
        pubsub.publish(
            crate::IDENTITY_ANNOUNCE_TOPIC.to_string(),
            Bytes::from(request),
        ),
    );
    if let (Err(t), Err(w)) = (&targeted, &warm) {
        #[cfg(test)]
        cache
            .diagnostics
            .terminal_both_carriers_failed
            .fetch_add(1, Ordering::Relaxed);
        return Err(format!(
            "both blob request carriers failed: targeted={t}; warm={w}"
        ));
    }
    if let Err(e) = &targeted {
        tracing::warn!(target: "announce.blob", %e, "targeted blob request carrier failed");
    }
    if let Err(e) = &warm {
        tracing::warn!(target: "announce.blob", %e, "warm blob request carrier failed");
    }

    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(BLOB_FETCH_TIMEOUT_SECS);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            #[cfg(test)]
            cache
                .diagnostics
                .terminal_deadline_elapsed
                .fetch_add(1, Ordering::Relaxed);
            return Err("announce blob fetch timed out".to_string());
        }
        let message = match tokio::time::timeout(remaining, responses.recv()).await {
            Ok(Some(message)) => message,
            Ok(None) => {
                #[cfg(test)]
                cache
                    .diagnostics
                    .terminal_subscription_closed
                    .fetch_add(1, Ordering::Relaxed);
                return Err("blob response subscription closed".to_string());
            }
            Err(_) => {
                #[cfg(test)]
                cache
                    .diagnostics
                    .terminal_deadline_elapsed
                    .fetch_add(1, Ordering::Relaxed);
                return Err("announce blob fetch timed out".to_string());
            }
        };
        let Some(payload) = message.payload.strip_prefix(ANNOUNCE_BLOB_RESPONSE_DOMAIN) else {
            // A request or foreign message on the topic — not ours.
            continue;
        };
        #[cfg(test)]
        cache
            .diagnostics
            .responses_seen
            .fetch_add(1, Ordering::Relaxed);
        let Some(response) = decode_blob_response(payload) else {
            #[cfg(test)]
            cache
                .diagnostics
                .responses_skipped_malformed
                .fetch_add(1, Ordering::Relaxed);
            continue;
        };
        // Responses for concurrent requests share this topic. Ignore other
        // digests; a matching candidate still passes the complete verifier.
        let Some(result) = select_and_verify_fetched_blob(
            &response.announcement_bytes,
            digest,
            expected_agent_id,
            0,
        ) else {
            #[cfg(test)]
            cache
                .diagnostics
                .responses_skipped_mismatched_digest
                .fetch_add(1, Ordering::Relaxed);
            continue;
        };
        return result.map_err(|e| {
            #[cfg(test)]
            cache.diagnostics.terminal_verifier_error.fetch_add(1, Ordering::Relaxed);

            tracing::warn!(
                target: "announce.blob",
                agent = %hex::encode(expected_agent_id.as_bytes()),
                machine = %machine_id.as_bytes().iter().map(|b| format!("{b:02x}")).take(8).collect::<String>(),
                cached_hits = cache.snapshot().blob_cache_hits,
                "fetched blob REJECTED by the verify gate: {e}"
            );
            e
        });
    }
}

/// `None` means this shared-topic response belongs to another digest: keep
/// waiting under the existing deadline. A matching candidate's verification
/// error remains terminal, and only a fully verified blob can be cached.
fn select_and_verify_fetched_blob(
    blob_bytes: &[u8],
    expected_digest: &[u8; 32],
    expected_agent_id: &identity::AgentId,
    payload_version: u64,
) -> Option<Result<CachedBlob, String>> {
    if blake3::hash(blob_bytes).as_bytes() != expected_digest {
        return None;
    }
    Some(verify_fetched_blob(
        blob_bytes,
        expected_digest,
        expected_agent_id,
        payload_version,
    ))
}

/// Verify a fetched blob against the expected digest and agent.
/// This is the SECURITY GATE — called before any cache insert.
///
/// The blob is the bincode of `(Option<UserId>, Option<AgentCertificate>)`
/// — the exact bytes [`crate::announce_v3::cert_digest`] commits to.
///
/// Gate order:
/// 1. `blake3(blob_bytes) == expected_digest` (byte-level match first —
///    nothing else runs on mismatched bytes).
/// 2. Deserialize the pair.
/// 3. Mirror `IdentityAnnouncement::verify`'s pairing rule:
///    - `(Some(user), Some(cert))` → `cert.verify()` AND
///      `cert.agent_id() == expected_agent_id` AND
///      `cert.user_id() == user` (the cert binds THIS agent + THIS user).
///    - `(None, None)` → anonymous, ok.
///    - mixed → reject (V2 pairing rule forbids user without cert and
///      cert without user).
///
/// Returns `Ok(CachedBlob)` only on full success.
pub fn verify_fetched_blob(
    blob_bytes: &[u8],
    expected_digest: &[u8; 32],
    expected_agent_id: &identity::AgentId,
    payload_version: u64,
) -> Result<CachedBlob, String> {
    // Step 1: digest match.
    let computed = blake3::hash(blob_bytes);
    if computed.as_bytes() != expected_digest {
        return Err(format!(
            "digest mismatch: expected {}, got {}",
            hex::encode(expected_digest),
            hex::encode(computed.as_bytes())
        ));
    }

    // Step 2: deserialize the pair.
    let (user_id, agent_certificate): (
        Option<identity::UserId>,
        Option<identity::AgentCertificate>,
    ) = bincode::deserialize(blob_bytes).map_err(|e| format!("deserialization failed: {e}"))?;

    // Step 3: the pairing rule — mirrors IdentityAnnouncement::verify.
    match (&user_id, &agent_certificate) {
        (Some(user), Some(cert)) => {
            cert.verify()
                .map_err(|e| format!("certificate verification failed: {e}"))?;
            let cert_agent = cert
                .agent_id()
                .map_err(|e| format!("certificate agent_id extraction failed: {e}"))?;
            if cert_agent != *expected_agent_id {
                return Err(format!(
                    "certificate is for another agent: cert={}, expected={}",
                    hex::encode(cert_agent.as_bytes()),
                    hex::encode(expected_agent_id.as_bytes())
                ));
            }
            let cert_user = cert
                .user_id()
                .map_err(|e| format!("certificate user_id extraction failed: {e}"))?;
            if cert_user != *user {
                return Err("certificate user does not match the paired user_id".to_string());
            }
        }
        (None, None) => {} // anonymous — the digest commits to emptiness
        (Some(_), None) | (None, Some(_)) => {
            return Err("mixed pair rejected: user without cert or cert without user".to_string());
        }
    }

    // Verified — safe to cache.
    Ok(CachedBlob {
        digest: *expected_digest,
        payload_version,
        user_id,
        agent_certificate,
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

/// Decode a domain-stripped blob request from the wire.
fn decode_blob_request_from(encoded: &[u8]) -> Option<AnnounceBlobRequest> {
    bincode::deserialize(encoded).ok()
}

/// Spawn the blob responder: subscribes the targeted (`ANNOUNCE_BLOB_TOPIC`)
/// and warm (identity announce topic) carriers, answers every verified
/// domain-prefixed request with [`AnnounceBlobCache::serve_request`]'s pair
/// bytes under `ANNOUNCE_BLOB_RESPONSE_DOMAIN`. Mirrors the caps
/// warm-targeted-request responder (`dm_capability_service.rs`), including
/// a 1-response-per-second PER-DIGEST coalescing window so a burst of
/// requests cannot turn into a blob storm without starving unrelated
/// digests (#656).
///
/// `own_pair` is read live per request, so consent changes (a new user→agent
/// certificate) are served without a restart.
pub async fn spawn_blob_responder(
    pubsub: Arc<PubSubManager>,
    cache: Arc<AnnounceBlobCache>,
    own_pair: SharedCertPair,
) -> crate::error::NetworkResult<tokio::task::JoinHandle<()>> {
    let mut targeted = pubsub.subscribe(ANNOUNCE_BLOB_TOPIC.to_string()).await;
    let mut warm = pubsub
        .subscribe(crate::IDENTITY_ANNOUNCE_TOPIC.to_string())
        .await;

    let handle = tokio::spawn(async move {
        let mut last_response_by_digest: HashMap<[u8; 32], std::time::Instant> = HashMap::new();
        loop {
            // Drain whichever carrier delivers first; both decode the same
            // domain-prefixed request shape.
            let Some(message) = targeted.recv_from_either(&mut warm).await else {
                break;
            };
            if !message.verified || message.sender.is_none() {
                continue;
            }
            let Some(encoded) = message.payload.strip_prefix(ANNOUNCE_BLOB_REQUEST_DOMAIN) else {
                // An announce or foreign payload on the shared carrier.
                continue;
            };
            let Some(request) = decode_blob_request_from(encoded) else {
                continue;
            };
            // Only verified, sender-bearing, domain-matched and decoded requests.
            #[cfg(test)]
            cache
                .diagnostics
                .verified_requests_decoded
                .fetch_add(1, Ordering::Relaxed);
            let (own_user, own_cert) = own_pair
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let Some(pair_bytes) = cache
                .serve_request(&request.digest, &own_user, &own_cert)
                .await
            else {
                #[cfg(test)]
                cache
                    .diagnostics
                    .unknown_digest
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    target: "announce.blob",
                    digest = %hex::encode(request.digest),
                    "blob request for an unknown digest — not served"
                );
                continue;
            };
            #[cfg(test)]
            cache
                .diagnostics
                .pair_available
                .fetch_add(1, Ordering::Relaxed);
            // Coalesce per digest: at most one response per window per
            // blob, like the caps responder. A dropped response is retried
            // by the next beat. The window is keyed by digest (#656) so a
            // busy blob never silences unrelated digests.
            let now = std::time::Instant::now();
            let within_window = last_response_by_digest
                .get(&request.digest)
                .is_some_and(|last| {
                    now.duration_since(*last)
                        < std::time::Duration::from_secs(MIN_RESPONSE_INTERVAL_SECS)
                });
            if within_window {
                #[cfg(test)]
                cache
                    .diagnostics
                    .coalesced_dropped
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            last_response_by_digest.insert(request.digest, now);
            // Wrap the pair bytes in the typed response envelope so the
            // fetcher's decode_blob_response round-trips (a bare pair tuple
            // does not deserialize as AnnounceBlobResponse).
            let mut wire = encode_blob_response(pair_bytes);
            let mut prefixed = Vec::with_capacity(ANNOUNCE_BLOB_RESPONSE_DOMAIN.len() + wire.len());
            prefixed.extend_from_slice(ANNOUNCE_BLOB_RESPONSE_DOMAIN);
            prefixed.append(&mut wire);
            if let Err(e) = pubsub
                .publish(ANNOUNCE_BLOB_TOPIC.to_string(), Bytes::from(prefixed))
                .await
            {
                #[cfg(test)]
                cache
                    .diagnostics
                    .publish_failed_local
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(target: "announce.blob", %e, "blob response publish failed");
            } else {
                #[cfg(test)]
                cache
                    .diagnostics
                    .response_publish_ok_local
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    Ok(handle)
}

// ---------------------------------------------------------------------------
// Tests — EXTEND this module, never replace pre-existing tests.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    /// SECURITY (digest-spoof attribution): an attacker can put a VICTIM's
    /// cert digest inside their own validly-signed V3 announce. The receiver
    /// hit-path must refuse to merge a cached pair whose certificate binds a
    /// different agent — otherwise the attacker's cache entry inherits the
    /// victim's user attribution. This pins the binding predicate the
    /// discovery arm uses before merging.
    #[test]
    fn cached_pair_never_merges_into_a_different_agents_announcement() {
        let victim_user = crate::identity::UserKeypair::generate().unwrap();
        let victim_agent = crate::identity::AgentKeypair::generate().unwrap();
        let attacker_agent = crate::identity::AgentKeypair::generate().unwrap();
        let cert = crate::identity::AgentCertificate::issue(&victim_user, &victim_agent)
            .expect("cert issues");
        let merge_allowed = |cert: &crate::identity::AgentCertificate,
                             claimed: &crate::identity::AgentId| {
            cert.agent_id().is_ok_and(|id| id == *claimed)
        };
        assert!(
            merge_allowed(&cert, &victim_agent.agent_id()),
            "victim's own announcement must merge its pair"
        );
        assert!(
            !merge_allowed(&cert, &attacker_agent.agent_id()),
            "attacker claiming the victim's digest must NOT inherit the pair"
        );
    }

    use super::*;
    use crate::identity::{AgentCertificate, AgentKeypair, UserKeypair};

    /// Build a real issued certificate binding user→agent.
    fn issued_cert() -> (AgentCertificate, UserKeypair, AgentKeypair) {
        let user_kp = UserKeypair::generate().expect("user keypair");
        let agent_kp = AgentKeypair::generate().expect("agent keypair");
        let cert = AgentCertificate::issue(&user_kp, &agent_kp).expect("cert issues");
        (cert, user_kp, agent_kp)
    }

    /// Bincode of the pair — the exact bytes the digest commits to.
    fn pair_bytes(user_id: &Option<identity::UserId>, cert: &Option<AgentCertificate>) -> Vec<u8> {
        bincode::serialize(&(user_id, cert)).expect("serialize pair")
    }

    #[test]
    fn blob_response_selection_interleaved_requests_reach_their_own_match() {
        let (cert_a, user_a, agent_a) = issued_cert();
        let (cert_b, user_b, agent_b) = issued_cert();
        let bytes_a = pair_bytes(&Some(user_a.user_id()), &Some(cert_a));
        let bytes_b = pair_bytes(&Some(user_b.user_id()), &Some(cert_b));
        let digest_a = *blake3::hash(&bytes_a).as_bytes();
        let digest_b = *blake3::hash(&bytes_b).as_bytes();
        assert_ne!(digest_a, digest_b);

        // Both fetchers see the same interleaving, B then A. The former
        // unconditional verification terminated fetch A on the first B.
        for (digest, agent) in [
            (digest_a, agent_a.agent_id()),
            (digest_b, agent_b.agent_id()),
        ] {
            let selected = [&bytes_b, &bytes_a]
                .into_iter()
                .find_map(|bytes| select_and_verify_fetched_blob(bytes, &digest, &agent, 7))
                .expect("each request selects its own response")
                .expect("the matching pair verifies");
            assert_eq!(selected.digest, digest);
            assert_eq!(selected.payload_version, 7);
            assert_eq!(
                selected.agent_certificate.unwrap().agent_id().unwrap(),
                agent
            );
        }
    }

    #[test]
    fn blob_response_selection_unrelated_only_has_no_terminal_result() {
        let (_, _, agent) = issued_cert();
        let expected = *blake3::hash(b"requested blob").as_bytes();
        for bytes in [
            b"unrelated response".as_slice(),
            b"another response".as_slice(),
        ] {
            assert!(
                select_and_verify_fetched_blob(bytes, &expected, &agent.agent_id(), 0).is_none()
            );
        }
        // Selection does not introduce a retry or own a clock: the caller
        // continues to enforce the original response-wait deadline.
    }

    #[test]
    fn blob_response_selection_matching_malformed_and_mixed_pairs_still_reject() {
        let (_, user, agent) = issued_cert();
        for bytes in [vec![0xff], pair_bytes(&Some(user.user_id()), &None)] {
            let digest = *blake3::hash(&bytes).as_bytes();
            let result = select_and_verify_fetched_blob(&bytes, &digest, &agent.agent_id(), 0)
                .expect("matching digest must reach the verifier");
            assert!(
                result.is_err(),
                "matching digest alone cannot authorize a blob"
            );
        }
    }

    #[test]
    fn blob_response_selection_matching_wrong_agent_and_forged_cert_still_reject() {
        let (cert, user, agent) = issued_cert();
        let other_agent = AgentKeypair::generate().expect("other agent");
        let signature = cert.signature_bytes().to_vec();
        let mut bytes = pair_bytes(&Some(user.user_id()), &Some(cert));
        let digest = *blake3::hash(&bytes).as_bytes();
        let result = select_and_verify_fetched_blob(&bytes, &digest, &other_agent.agent_id(), 0)
            .expect("matching digest must reach agent binding");
        assert!(result.unwrap_err().contains("another agent"));

        // Locate actual signature data via its public accessor, not a guessed
        // trailing offset (the final byte encodes the not_after Option).
        let offsets: Vec<_> = bytes
            .windows(signature.len())
            .enumerate()
            .filter_map(|(offset, window)| (window == signature).then_some(offset))
            .collect();
        assert_eq!(offsets.len(), 1, "signature data must occur exactly once");
        bytes[offsets[0]] ^= 0xff;
        let (_, decoded_cert): (Option<identity::UserId>, Option<AgentCertificate>) =
            bincode::deserialize(&bytes).expect("signature mutation preserves pair decoding");
        let decoded_cert = decoded_cert.expect("mutated pair still contains a certificate");
        assert_ne!(decoded_cert.signature_bytes(), signature);
        assert!(
            decoded_cert.verify().is_err(),
            "mutated signature must fail verification"
        );
        let forged_digest = *blake3::hash(&bytes).as_bytes();
        let result = select_and_verify_fetched_blob(&bytes, &forged_digest, &agent.agent_id(), 0)
            .expect("matching forged digest must reach certificate verification");
        assert!(
            result
                .unwrap_err()
                .starts_with("certificate verification failed:"),
            "matching forged certificate must fail the signature gate, not decoding"
        );
    }

    /// CROSS-MODULE CONSISTENCY: the digest computed by
    /// `announce_v3::cert_digest` over the pair is exactly what
    /// `verify_fetched_blob` accepts. This is the test that would have
    /// caught the full-announcement hashing mismatch.
    #[tokio::test]
    async fn cert_digest_matches_verify_fetched_blob_acceptance() {
        let (cert, user_kp, agent_kp) = issued_cert();
        let user_id = Some(user_kp.user_id());
        let agent_id = agent_kp.agent_id();
        // The V3 side computes the digest...
        let digest = crate::announce_v3::cert_digest(&user_id, &Some(cert.clone()));
        // ...and the blob side must accept those exact bytes under it.
        let bytes = pair_bytes(&user_id, &Some(cert));
        let accepted = verify_fetched_blob(&bytes, &digest, &agent_id, 1);
        assert!(
            accepted.is_ok(),
            "blob verify must accept what cert_digest commits to: {:?}",
            accepted.err()
        );
    }

    /// Anonymous pair `(None, None)`: digest matches, no cert to verify —
    /// accepted. This is the steady-state case for cert-less agents.
    #[tokio::test]
    async fn anonymous_pair_is_accepted() {
        let agent_kp = AgentKeypair::generate().expect("agent keypair");
        let bytes = pair_bytes(&None, &None);
        let digest = crate::announce_v3::cert_digest(&None, &None);
        assert!(verify_fetched_blob(&bytes, &digest, &agent_kp.agent_id(), 1).is_ok());
    }

    /// SECURITY: a cert for agent A is rejected when the fetch expected
    /// agent B — the digest alone must not vouch for the binding.
    #[tokio::test]
    async fn cert_for_wrong_agent_is_rejected() {
        let (cert, user_kp, _) = issued_cert();
        let other_agent = AgentKeypair::generate().expect("other agent");
        let user_id = Some(user_kp.user_id());
        let digest = crate::announce_v3::cert_digest(&user_id, &Some(cert.clone()));
        let bytes = pair_bytes(&user_id, &Some(cert));

        let result = verify_fetched_blob(&bytes, &digest, &other_agent.agent_id(), 1);
        assert!(result.is_err(), "cross-agent cert must be rejected");
        assert!(
            result.unwrap_err().contains("another agent"),
            "the error should name the agent binding failure"
        );
    }

    /// SECURITY: a forged certificate (tampered signature bytes) is
    /// rejected even when the digest matches the tampered bytes — verify
    /// runs on the deserialized pair, not just the hash. Tamper at the
    /// bincode level (the signature field is private): flip a byte in the
    /// tail of the serialized pair, recompute the digest over the tampered
    /// bytes, and the gate must still reject.
    #[tokio::test]
    async fn forged_certificate_is_rejected_before_cache() {
        let (cert, user_kp, agent_kp) = issued_cert();
        let user_id = Some(user_kp.user_id());
        let mut bytes = pair_bytes(&user_id, &Some(cert));

        // Flip a byte near the end (inside the cert's signature region).
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;

        // Digest "matches" the tampered bytes — the attacker controls both.
        let digest: [u8; 32] = blake3::hash(&bytes).into();

        let result = verify_fetched_blob(&bytes, &digest, &agent_kp.agent_id(), 1);
        assert!(
            result.is_err(),
            "forged certificate must be rejected before caching even with a matching digest"
        );
    }

    /// SECURITY: digest mismatch — the fetched bytes don't hash to the
    /// requested digest, so the blob is rejected before anything else runs.
    #[tokio::test]
    async fn digest_mismatch_rejected() {
        let (cert, user_kp, agent_kp) = issued_cert();
        let user_id = Some(user_kp.user_id());
        let bytes = pair_bytes(&user_id, &Some(cert));
        let wrong_digest: [u8; 32] = [0xAB; 32]; // deliberately wrong

        let result = verify_fetched_blob(&bytes, &wrong_digest, &agent_kp.agent_id(), 1);
        assert!(result.is_err(), "digest mismatch must be rejected");
        assert!(
            result.unwrap_err().contains("digest mismatch"),
            "the error should name the digest mismatch"
        );
    }

    /// SECURITY: mixed pair — user without cert — rejected per the V2
    /// pairing rule.
    #[tokio::test]
    async fn mixed_pair_is_rejected() {
        let user_kp = UserKeypair::generate().expect("user keypair");
        let agent_kp = AgentKeypair::generate().expect("agent keypair");
        let user_id = Some(user_kp.user_id());
        let bytes = pair_bytes(&user_id, &None);
        let digest = crate::announce_v3::cert_digest(&user_id, &None);

        let result = verify_fetched_blob(&bytes, &digest, &agent_kp.agent_id(), 1);
        assert!(result.is_err(), "user-without-cert must be rejected");
        assert!(
            result.unwrap_err().contains("mixed pair"),
            "the error should name the mixed-pair rule"
        );
    }

    /// Disk round-trip: what goes in comes back out after a reload.
    #[tokio::test]
    async fn blob_cache_disk_round_trip() {
        let (cert, user_kp, agent_kp) = issued_cert();
        let user_id = Some(user_kp.user_id());
        let digest = AnnounceBlobCache::digest_of(&user_id, &Some(cert.clone()));

        {
            let cache = AnnounceBlobCache::new(Some(std::path::PathBuf::from(
                "/tmp/x0x-blob-roundtrip-test.bin",
            )));
            cache
                .insert_verified(CachedBlob {
                    digest,
                    payload_version: 1,
                    user_id,
                    agent_certificate: Some(cert),
                    fetched_at_unix: 1_800_000_000,
                })
                .await;
        }

        // New cache instance loads from disk.
        let reloaded = AnnounceBlobCache::new(Some(std::path::PathBuf::from(
            "/tmp/x0x-blob-roundtrip-test.bin",
        )));
        let hit = reloaded.get(&digest).await;
        assert!(hit.is_some(), "blob must survive disk round-trip");
        let blob = hit.unwrap();
        assert_eq!(blob.user_id, user_id);
        assert_eq!(
            blob.agent_certificate.as_ref().map(|c| c.agent_id().ok()),
            Some(Some(agent_kp.agent_id()))
        );
        std::fs::remove_file("/tmp/x0x-blob-roundtrip-test.bin").ok();
    }

    /// LRU cap: inserting more than BLOB_CACHE_MAX_ENTRIES evicts the
    /// least-recently-used entry.
    #[tokio::test]
    async fn lru_cap_evicts_least_recently_used() {
        let cache = AnnounceBlobCache::new(None); // no disk

        // Fill to cap + 1. Digests are BLAKE3 of the index — distinct even
        // past u8 wraparound (a naive `[i as u8; 32]` collides at i=256).
        // One pair shared across entries: the payload is opaque to the
        // LRU logic and keygen is the expensive part.
        let shared_user: Option<identity::UserId> = None;
        let shared_cert: Option<AgentCertificate> = None;
        for i in 0..=BLOB_CACHE_MAX_ENTRIES {
            let digest: [u8; 32] = blake3::hash(&i.to_le_bytes()).into();
            let blob = CachedBlob {
                digest,
                payload_version: 1,
                user_id: shared_user,
                agent_certificate: shared_cert.clone(),
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

    /// serve_request: our own current pair is served when the digest
    /// matches it.
    #[tokio::test]
    async fn serve_request_answers_from_own_pair() {
        let (cert, user_kp, _agent_kp) = issued_cert();
        let user_id = Some(user_kp.user_id());
        let cache = AnnounceBlobCache::new(None);
        let digest = crate::announce_v3::cert_digest(&user_id, &Some(cert.clone()));

        let serve_cert = cert.clone();
        let expected = pair_bytes(&user_id, &Some(cert));
        let served = cache
            .serve_request(&digest, &user_id, &Some(serve_cert))
            .await
            .expect("own pair must be served");
        assert_eq!(served, expected);
    }

    /// serve_request: an unknown digest (not ours, not cached) gets None.
    #[tokio::test]
    async fn serve_request_unknown_digest_returns_none() {
        let cache = AnnounceBlobCache::new(None);
        let unknown: [u8; 32] = [0xCD; 32];
        assert!(cache.serve_request(&unknown, &None, &None).await.is_none());
    }

    /// serve_request (#656): a digest that only exists in OUR CACHE (a
    /// peer's blob) must NOT be served. Cache-first serving turned every
    /// node that had ever cached peer X's blob into a responder for X, so
    /// one request drew a broadcast response from every cache holder.
    #[tokio::test]
    async fn serve_request_never_serves_a_cached_peer_blob() {
        let (cert, user_kp, _agent_kp) = issued_cert();
        let peer_user_id = Some(user_kp.user_id());
        let cache = AnnounceBlobCache::new(None);
        let digest = crate::announce_v3::cert_digest(&peer_user_id, &Some(cert.clone()));
        cache
            .insert_verified(CachedBlob {
                digest,
                payload_version: 1,
                user_id: peer_user_id,
                agent_certificate: Some(cert),
                fetched_at_unix: 1,
            })
            .await;

        // The cache HITS for the peer digest...
        assert!(cache.get(&digest).await.is_some());
        // ...but serving is owner-only: with our own (different, anonymous)
        // pair the request goes unanswered.
        assert!(
            cache.serve_request(&digest, &None, &None).await.is_none(),
            "a cached peer blob must not be served by a non-owner"
        );
    }

    /// serve_request (#656 round 2): the anonymous digest must not be
    /// served even by a node whose own pair IS `(None, None)` — user keys
    /// are opt-in, so every cert-less node shares that digest and a
    /// request for it would draw a response from each of them. Production
    /// requesters never ask for it (`fetch_warranted` gates the fetch).
    #[tokio::test]
    async fn serve_request_never_serves_the_shared_anonymous_digest() {
        let cache = AnnounceBlobCache::new(None);
        let anon = crate::announce_v3::anonymous_cert_digest();
        assert!(
            cache.serve_request(&anon, &None, &None).await.is_none(),
            "the anonymous digest is shared by every cert-less node — it has no unique owner"
        );
    }

    // ── Hermetic protocol tests (issue #417: no prod dialing — local
    //    pubsub delivery only, mirroring the caps-service test harness) ──

    mod protocol {
        use super::super::*;
        use super::{issued_cert, pair_bytes};
        use crate::gossip::SigningContext;
        use crate::network::{NetworkConfig, NetworkNode};
        use std::sync::Arc;
        use std::time::Duration;

        /// Explicit test-only network config (#417/#337): loopback bind, no
        /// seeds, discovery/port-mapping off. Still a real socket constructor.
        fn test_network_config() -> NetworkConfig {
            NetworkConfig {
                bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
                bootstrap_nodes: Vec::new(),
                mdns_enabled: false,
                port_mapping_enabled: false,
                ..NetworkConfig::default()
            }
        }

        async fn make_pubsub() -> Arc<PubSubManager> {
            let node = Arc::new(
                NetworkNode::new(test_network_config(), None, None)
                    .await
                    .expect("network node"),
            );
            let kp = crate::identity::AgentKeypair::generate().expect("keypair");
            let signing = Arc::new(SigningContext::from_keypair(&kp));
            Arc::new(PubSubManager::new(node, Some(signing)).expect("pubsub"))
        }

        /// Wait until `cache` holds `digest` (the fetch task fills it
        /// asynchronously) or fail after `secs`.
        async fn wait_for_blob(
            cache: &Arc<AnnounceBlobCache>,
            digest: &[u8; 32],
            secs: u64,
        ) -> Option<Arc<CachedBlob>> {
            let deadline = std::time::Instant::now() + Duration::from_secs(secs);
            loop {
                if let Some(hit) = cache.get(digest).await {
                    return Some(hit);
                }
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        /// Two-agent loopback: a consented agent serves its pair via the
        /// responder; the peer's ensure_blob misses, fetches, verifies, and
        /// the cache gains the cert+user. Second ensure_blob hits.
        #[tokio::test]
        async fn two_agent_fetch_fills_peer_cache() {
            let (cert, user_kp, agent_kp) = issued_cert();
            let user_id = Some(user_kp.user_id());
            let agent_id = agent_kp.agent_id();
            let machine_id = crate::identity::MachineId([0x77; 32]);
            let digest = crate::announce_v3::cert_digest(&user_id, &Some(cert.clone()));

            let pubsub = make_pubsub().await;
            // Serving agent: it OWNS the pair (owner-only serving, #656) and
            // still carries a pre-cached copy — proving a cache hit alone no
            // longer makes a node a responder.
            let serving_cache = Arc::new(AnnounceBlobCache::new(None));
            serving_cache
                .insert_verified(CachedBlob {
                    digest,
                    payload_version: 7,
                    user_id,
                    agent_certificate: Some(cert.clone()),
                    fetched_at_unix: 1,
                })
                .await;
            let own_pair = shared_cert_pair(user_id, Some(cert.clone()));
            spawn_blob_responder(Arc::clone(&pubsub), serving_cache, own_pair)
                .await
                .expect("responder spawns");
            // Let the responder's subscriptions register before fetching
            // (same registration race the caps-service test sleeps for).
            tokio::time::sleep(Duration::from_millis(300)).await;

            // Fetching agent: empty cache. Miss → None, fetch fires.
            let fetching_cache = Arc::new(AnnounceBlobCache::new(None));
            let immediate = fetching_cache
                .ensure_blob(&pubsub, &digest, 7, &agent_id, &machine_id)
                .await;
            assert!(
                immediate.is_none(),
                "miss must return None (no-block contract)"
            );

            let filled = wait_for_blob(&fetching_cache, &digest, 8)
                .await
                .expect("fetch must fill the cache");
            assert_eq!(filled.user_id, user_id);
            assert_eq!(
                filled
                    .agent_certificate
                    .as_ref()
                    .and_then(|c| c.agent_id().ok()),
                Some(agent_id),
                "the fetched cert must bind the announced agent"
            );
            assert_eq!(filled.payload_version, 7, "version overlays the fetch");

            // Hit path: immediate Some.
            let hit = fetching_cache
                .ensure_blob(&pubsub, &digest, 7, &agent_id, &machine_id)
                .await;
            assert!(hit.is_some(), "second call must hit the filled cache");

            let stats = fetching_cache.snapshot();
            assert!(stats.blob_fetches_ok >= 1, "metering must count the fetch");
        }

        /// #656 fixture: A announces (owns) a pair; B and C have ALREADY
        /// cached A's blob; D requests it. Business rule: a cert blob is
        /// served by its OWNER — a mesh of N caches is a mesh of N
        /// amplifiers, and under cache-first serving this exact fixture put
        /// THREE responses on the wire for one request. Then, still inside
        /// what used to be one global 1 s coalescing window, D requests C's
        /// digest: it must be answered, proving the window is per digest
        /// and one busy blob cannot starve unrelated owners.
        #[tokio::test]
        async fn blob_request_is_answered_once_by_the_owner_only() {
            let (cert_a, user_a, _) = issued_cert();
            let (cert_b, user_b, _) = issued_cert();
            let (cert_c, user_c, _) = issued_cert();
            let user_a = Some(user_a.user_id());
            let user_b = Some(user_b.user_id());
            let user_c = Some(user_c.user_id());
            let digest_a = crate::announce_v3::cert_digest(&user_a, &Some(cert_a.clone()));
            let digest_c = crate::announce_v3::cert_digest(&user_c, &Some(cert_c.clone()));

            let pubsub = make_pubsub().await;

            // Fleet-wide response counter: every domain-prefixed blob
            // RESPONSE on the topic, keyed by the digest of the pair bytes
            // it carries (the same match rule the fetcher uses).
            let mut counter_sub = pubsub.subscribe(ANNOUNCE_BLOB_TOPIC.to_string()).await;
            let counts = Arc::new(std::sync::Mutex::new(HashMap::<[u8; 32], usize>::new()));
            let counter_counts = Arc::clone(&counts);
            tokio::spawn(async move {
                while let Some(message) = counter_sub.recv().await {
                    let Some(payload) = message.payload.strip_prefix(ANNOUNCE_BLOB_RESPONSE_DOMAIN)
                    else {
                        continue;
                    };
                    let Some(response) = decode_blob_response(payload) else {
                        continue;
                    };
                    let digest: [u8; 32] = blake3::hash(&response.announcement_bytes).into();
                    *counter_counts
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .entry(digest)
                        .or_insert(0) += 1;
                }
            });

            // A: owner of digest_a, empty cache — it serves from its own
            // live pair.
            spawn_blob_responder(
                Arc::clone(&pubsub),
                Arc::new(AnnounceBlobCache::new(None)),
                shared_cert_pair(user_a, Some(cert_a.clone())),
            )
            .await
            .expect("responder A spawns");
            // B and C: owners of their OWN pairs, with A's blob already
            // cached — the cache-first amplifier fixture.
            for (user, cert) in [(user_b, cert_b), (user_c, cert_c.clone())] {
                let cache = Arc::new(AnnounceBlobCache::new(None));
                cache
                    .insert_verified(CachedBlob {
                        digest: digest_a,
                        payload_version: 7,
                        user_id: user_a,
                        agent_certificate: Some(cert_a.clone()),
                        fetched_at_unix: 1,
                    })
                    .await;
                spawn_blob_responder(
                    Arc::clone(&pubsub),
                    cache,
                    shared_cert_pair(user, Some(cert)),
                )
                .await
                .expect("responder spawns");
            }
            // Let the responders' subscriptions register (same
            // registration race the caps-service tests sleep for).
            tokio::time::sleep(Duration::from_millis(300)).await;

            let count = |digest: &[u8; 32]| {
                counts
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(digest)
                    .copied()
                    .unwrap_or(0)
            };
            let requester = crate::identity::AgentKeypair::generate()
                .expect("requester keypair")
                .agent_id();

            // D requests A's blob. Exactly one response may exist
            // fleet-wide: the owner's.
            pubsub
                .publish(
                    ANNOUNCE_BLOB_TOPIC.to_string(),
                    Bytes::from(encode_blob_request(&digest_a, &requester)),
                )
                .await
                .expect("publish request for A's blob");
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while count(&digest_a) < 1 && std::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            // Quiet period: no further responses may arrive for the same
            // request (this is the exact-count assertion, not a lower
            // bound — cache-first serving produced three here).
            tokio::time::sleep(Duration::from_millis(400)).await;
            assert_eq!(
                count(&digest_a),
                1,
                "exactly ONE publish fleet-wide: the owner's"
            );

            // Inside the old 1 s global window, D requests C's blob. The
            // per-digest window must let C answer: under the global
            // instant, B and C had just burned their window answering for
            // A, so C's own digest was silently starved.
            pubsub
                .publish(
                    ANNOUNCE_BLOB_TOPIC.to_string(),
                    Bytes::from(encode_blob_request(&digest_c, &requester)),
                )
                .await
                .expect("publish request for C's blob");
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while count(&digest_c) < 1 && std::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
            assert_eq!(
                count(&digest_c),
                1,
                "a second digest inside the old window must still be answered, exactly once"
            );
            assert_eq!(count(&digest_a), 1, "no late responses for A's blob");
        }

        /// #656 round 2 — the discriminating test for the PER-DIGEST
        /// window. Owner-only serving leaves one responder with one
        /// digest, so the only way a single responder serves two digests
        /// inside one window is a live pair rotation (`own_pair` is read
        /// per request, so a consent change swaps the served digest).
        /// Under the old single global instant, answering the OLD digest
        /// burned the responder's whole 1 s window and silently starved
        /// the NEW digest; per-digest tracking answers both. Fails on the
        /// pre-fix global-window code with owner-only serving kept.
        #[tokio::test]
        async fn pair_rotation_is_not_starved_by_the_coalescing_window() {
            let (cert_old, user_old, _) = issued_cert();
            let (cert_new, user_new, _) = issued_cert();
            let user_old = Some(user_old.user_id());
            let user_new = Some(user_new.user_id());
            let digest_old = crate::announce_v3::cert_digest(&user_old, &Some(cert_old.clone()));
            let digest_new = crate::announce_v3::cert_digest(&user_new, &Some(cert_new.clone()));

            let pubsub = make_pubsub().await;
            let mut counter_sub = pubsub.subscribe(ANNOUNCE_BLOB_TOPIC.to_string()).await;
            let counts = Arc::new(std::sync::Mutex::new(HashMap::<[u8; 32], usize>::new()));
            let counter_counts = Arc::clone(&counts);
            tokio::spawn(async move {
                while let Some(message) = counter_sub.recv().await {
                    let Some(payload) = message.payload.strip_prefix(ANNOUNCE_BLOB_RESPONSE_DOMAIN)
                    else {
                        continue;
                    };
                    let Some(response) = decode_blob_response(payload) else {
                        continue;
                    };
                    let digest: [u8; 32] = blake3::hash(&response.announcement_bytes).into();
                    *counter_counts
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .entry(digest)
                        .or_insert(0) += 1;
                }
            });

            let own_pair = shared_cert_pair(user_old, Some(cert_old));
            spawn_blob_responder(
                Arc::clone(&pubsub),
                Arc::new(AnnounceBlobCache::new(None)),
                Arc::clone(&own_pair),
            )
            .await
            .expect("responder spawns");
            tokio::time::sleep(Duration::from_millis(300)).await;

            let requester = crate::identity::AgentKeypair::generate()
                .expect("requester keypair")
                .agent_id();
            pubsub
                .publish(
                    ANNOUNCE_BLOB_TOPIC.to_string(),
                    Bytes::from(encode_blob_request(&digest_old, &requester)),
                )
                .await
                .expect("publish request for the old pair");
            let count = |digest: &[u8; 32]| {
                counts
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(digest)
                    .copied()
                    .unwrap_or(0)
            };
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while count(&digest_old) < 1 && std::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            assert_eq!(count(&digest_old), 1, "the old pair is served once");

            // Rotate the live pair (a consent change) and immediately —
            // well inside the old 1 s window — request the new digest.
            own_pair
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone_from(&(user_new, Some(cert_new)));
            pubsub
                .publish(
                    ANNOUNCE_BLOB_TOPIC.to_string(),
                    Bytes::from(encode_blob_request(&digest_new, &requester)),
                )
                .await
                .expect("publish request for the rotated pair");
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while count(&digest_new) < 1 && std::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
            assert_eq!(
                count(&digest_new),
                1,
                "a fresh digest must not be starved by a recent serve of an unrelated digest"
            );
        }

        /// Forged responder: serves tampered pair bytes whose digest DOES
        /// match the tampered bytes (attacker controls both). The verify
        /// gate must reject — the cache stays empty and the failure meters.
        #[tokio::test]
        async fn forged_responder_is_rejected() {
            let (cert, user_kp, agent_kp) = issued_cert();
            let user_id = Some(user_kp.user_id());
            let agent_id = agent_kp.agent_id();
            let machine_id = crate::identity::MachineId([0x88; 32]);

            let pubsub = make_pubsub().await;
            let requesting_cache = Arc::new(AnnounceBlobCache::new(None));

            // Subscribe + answer with tampered bytes directly (no honest
            // responder): flip a signature byte, digest the tampered bytes.
            let mut tampered = pair_bytes(&user_id, &Some(cert));
            let last = tampered.len() - 1;
            tampered[last] ^= 0xFF;
            let digest: [u8; 32] = blake3::hash(&tampered).into();

            let forger_pubsub = Arc::clone(&pubsub);
            tokio::spawn(async move {
                let mut reqs = forger_pubsub
                    .subscribe(ANNOUNCE_BLOB_TOPIC.to_string())
                    .await;
                while let Some(message) = reqs.recv().await {
                    if message
                        .payload
                        .strip_prefix(ANNOUNCE_BLOB_REQUEST_DOMAIN)
                        .is_some()
                    {
                        let mut wire = encode_blob_response(tampered.clone());
                        let mut prefixed =
                            Vec::with_capacity(ANNOUNCE_BLOB_RESPONSE_DOMAIN.len() + wire.len());
                        prefixed.extend_from_slice(ANNOUNCE_BLOB_RESPONSE_DOMAIN);
                        prefixed.append(&mut wire);
                        let _ = forger_pubsub
                            .publish(ANNOUNCE_BLOB_TOPIC.to_string(), Bytes::from(prefixed))
                            .await;
                        break; // one forged answer is enough
                    }
                }
            });

            tokio::time::sleep(Duration::from_millis(300)).await;
            requesting_cache
                .ensure_blob(&pubsub, &digest, 1, &agent_id, &machine_id)
                .await;
            tokio::time::sleep(Duration::from_millis(500)).await;

            assert!(
                requesting_cache.get(&digest).await.is_none(),
                "the forged blob must never enter the cache"
            );
            let stats = requesting_cache.snapshot();
            assert!(
                stats.blob_fetches_failed >= 1,
                "the rejection must meter as a failed fetch"
            );
        }

        /// The receiver-arm skip rule: anonymous digests never warrant a
        /// fetch — `fetch_warranted` is the single definition.
        #[test]
        fn anonymous_digest_never_fetches() {
            let anon = crate::announce_v3::anonymous_cert_digest();
            assert!(!fetch_warranted(&anon), "anonymous digest must not fetch");
            let real = crate::announce_v3::cert_digest(
                &Some(
                    crate::identity::UserKeypair::generate()
                        .expect("kp")
                        .user_id(),
                ),
                &None,
            );
            assert!(fetch_warranted(&real), "a real digest must fetch");
        }

        /// Protocol safety net, inverted for owner-only serving (#656
        /// round 2): even if a caller ignores the fetch-warranted skip
        /// rule and asks for the anonymous digest, the responder stays
        /// SILENT — that digest is shared by every cert-less node, so it
        /// has no unique owner to answer. The stray request is harmless:
        /// nothing is served, nothing leaks, and the fetcher's own
        /// 5 s deadline ends it (metered as a failed fetch).
        #[tokio::test]
        async fn anonymous_digest_never_draws_a_response() {
            let pubsub = make_pubsub().await;
            let serving_cache = Arc::new(AnnounceBlobCache::new(None));
            // The responder's own pair IS the anonymous pair — exactly the
            // node that used to answer.
            let own_pair = shared_cert_pair(None, None);
            spawn_blob_responder(Arc::clone(&pubsub), serving_cache, own_pair)
                .await
                .expect("responder spawns");
            tokio::time::sleep(Duration::from_millis(300)).await;

            let anon_digest = crate::announce_v3::anonymous_cert_digest();
            let agent_id = crate::identity::AgentKeypair::generate()
                .expect("kp")
                .agent_id();
            let machine_id = crate::identity::MachineId([0x99; 32]);
            let fetching_cache = Arc::new(AnnounceBlobCache::new(None));
            fetching_cache
                .ensure_blob(&pubsub, &anon_digest, 0, &agent_id, &machine_id)
                .await;

            // Quiet window well past a local round-trip: no response may
            // arrive, and therefore no cache entry.
            tokio::time::sleep(Duration::from_millis(1_500)).await;
            assert!(
                fetching_cache.get(&anon_digest).await.is_none(),
                "the anonymous digest must never be served"
            );
        }
    }
}
