//! Mesh-wide DM-capability advertisement — so senders can discover which
//! peers support the gossip DM inbox path without needing an explicit
//! `AgentCard` exchange.
//!
//! This is complementary to the `AgentCard.dm_capabilities` field:
//! - AgentCards are the authoritative record (signed+authenticated when
//!   exchanged via invite links / card imports).
//! - The capability advert is the mesh-wide "I'm here and I support v1"
//!   broadcast that VPS bootstrap nodes and other mesh members use to
//!   discover each other's DM support without ever exchanging cards.
//!
//! Design trade-offs:
//! - Advert is signed by the sender's ML-DSA-65 agent key so receivers
//!   verify authenticity before caching.
//! - Cached entries have a TTL (15 minutes) so stale adverts don't
//!   persist forever; senders republish every 5 minutes during normal
//!   operation.
//! - This is NOT a presence system — it's strictly capability discovery.
//!   Presence + liveness continue to be handled by
//!   `saorsa-gossip-presence`.

use crate::dm::DmCapabilities;
use crate::identity::{AgentId, MachineId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Well-known gossip topic for capability adverts. Every x0x 0.18+ agent
/// subscribes on mesh join.
pub const DM_CAPABILITY_TOPIC: &str = "x0x/caps/v1";

/// Side-channel on which a late subscriber asks current mesh members to
/// republish their signed capability advert.
///
/// Capability adverts are intentionally ephemeral and normally refresh only
/// every five minutes. A daemon that joins after another peer's startup burst
/// would otherwise have to wait for that steady-state refresh. Requests are
/// themselves carried in authenticated pub/sub envelopes; responders still
/// build and sign a fresh advert, so this channel grants no capability and
/// cannot weaken the advert's AgentId + MachineId binding.
pub const DM_CAPABILITY_REQUEST_TOPIC: &str = "x0x/caps/v1/request";

/// Targeted capability refreshes use a distinct topic and wire version from
/// the legacy fleet request. Keeping them separate is the compatibility
/// boundary: pre-v2 responders subscribe only to [`DM_CAPABILITY_REQUEST_TOPIC`]
/// and therefore cannot misinterpret a targeted refresh as a fleet-wide one.
pub const DM_CAPABILITY_TARGETED_REQUEST_TOPIC: &str = "x0x/caps/v1/request/targeted-v2";

/// Domain-separation prefix for the advert signature bytes.
const ADVERT_SIGN_DOMAIN: &[u8] = b"x0x-caps-v1";

/// Cadence at which agents republish their advert.
pub const ADVERT_PUBLISH_INTERVAL_SECS: u64 = 300;

/// How long a cached advert remains usable before it's considered stale.
/// Must be > `ADVERT_PUBLISH_INTERVAL_SECS` so that a single missed
/// publish window doesn't evict the cache entry.
pub const ADVERT_CACHE_TTL_SECS: u64 = 900;

/// Signed capability advertisement broadcast on the mesh-wide capability
/// topic.
///
/// Domain-separated signed bytes:
/// `ADVERT_SIGN_DOMAIN || agent_id || machine_id || created_at_unix_ms
///  || postcard(capabilities)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityAdvert {
    /// Wire version. Bumped on breaking changes.
    pub protocol_version: u16,

    /// Advertising agent's id.
    pub agent_id: [u8; 32],

    /// Machine binding the ML-DSA-65 signature to a specific daemon
    /// process (so an agent_id can't advertise from two machines
    /// simultaneously — receivers can detect churn).
    pub machine_id: [u8; 32],

    /// Sender-local unix-ms at advert generation.
    pub created_at_unix_ms: u64,

    /// The advertised capabilities.
    pub capabilities: DmCapabilities,

    /// ML-DSA-65 signature over the domain-separated advert bytes.
    pub signature: Vec<u8>,
}

impl CapabilityAdvert {
    /// Build the canonical signed-bytes representation (what ML-DSA-65
    /// signs/verifies over).
    pub fn signed_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        let caps_bytes = postcard::to_stdvec(&self.capabilities)?;
        let mut out =
            Vec::with_capacity(ADVERT_SIGN_DOMAIN.len() + 2 + 32 + 32 + 8 + caps_bytes.len());
        out.extend_from_slice(ADVERT_SIGN_DOMAIN);
        out.extend_from_slice(&self.protocol_version.to_be_bytes());
        out.extend_from_slice(&self.agent_id);
        out.extend_from_slice(&self.machine_id);
        out.extend_from_slice(&self.created_at_unix_ms.to_be_bytes());
        out.extend_from_slice(&caps_bytes);
        Ok(out)
    }
}

/// In-memory cache of `AgentId → latest CapabilityAdvert`, with TTL
/// eviction.
///
/// Senders consult this cache before each `send_direct` call to determine
/// whether the recipient supports the gossip DM inbox path.
pub struct CapabilityStore {
    inner: Mutex<HashMap<[u8; 32], CachedAdvert>>,
    forced_test_misses: Mutex<std::collections::HashSet<[u8; 32]>>,
    ttl: Duration,
}

struct CachedAdvert {
    capabilities: DmCapabilities,
    machine_id: [u8; 32],
    seen_at: Instant,
    created_at_unix_ms: u64,
}

/// TTL-validated capability material together with the signed machine binding
/// from the same advert.
#[derive(Debug, Clone)]
pub struct CapabilityBinding {
    pub capabilities: DmCapabilities,
    pub machine_id: MachineId,
}

impl Default for CapabilityStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityStore {
    /// Construct an empty store with the default TTL.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            forced_test_misses: Mutex::new(std::collections::HashSet::new()),
            ttl: Duration::from_secs(ADVERT_CACHE_TTL_SECS),
        }
    }

    /// Custom-TTL store (primarily for tests).
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            forced_test_misses: Mutex::new(std::collections::HashSet::new()),
            ttl,
        }
    }

    /// Look up a peer's capability. Returns `None` if unknown or expired.
    pub fn lookup(&self, agent_id: &AgentId) -> Option<DmCapabilities> {
        self.lookup_binding(agent_id)
            .map(|binding| binding.capabilities)
    }

    /// Look up capability material and its exact signed advert machine.
    pub fn lookup_binding(&self, agent_id: &AgentId) -> Option<CapabilityBinding> {
        self.lookup_binding_at(agent_id, Instant::now())
    }

    /// Strict-send lookup plus proof that the disabled-by-default deterministic
    /// test control forced this exact miss. Production lookups always return
    /// `false`, preserving the refresh worker's early-cache optimization.
    pub(crate) fn lookup_binding_with_refresh_proof(
        &self,
        agent_id: &AgentId,
    ) -> (Option<CapabilityBinding>, bool) {
        self.lookup_binding_at_with_refresh_proof(agent_id, Instant::now())
    }

    /// Look up a peer's capability as of `now`.
    ///
    /// Test seam over [`lookup`](Self::lookup): production callers always go
    /// through [`lookup`](Self::lookup), which passes `Instant::now()`.
    /// Exposing the clock lets the TTL-expiry unit test advance time
    /// deterministically instead of sleeping past a wall-clock boundary —
    /// the documented CI flake for that assertion (issue: CI de-flake).
    pub fn lookup_at(&self, agent_id: &AgentId, now: Instant) -> Option<DmCapabilities> {
        self.lookup_binding_at(agent_id, now)
            .map(|binding| binding.capabilities)
    }

    /// Testable clock seam for [`Self::lookup_binding`].
    pub fn lookup_binding_at(&self, agent_id: &AgentId, now: Instant) -> Option<CapabilityBinding> {
        self.lookup_binding_at_with_refresh_proof(agent_id, now).0
    }

    fn lookup_binding_at_with_refresh_proof(
        &self,
        agent_id: &AgentId,
        now: Instant,
    ) -> (Option<CapabilityBinding>, bool) {
        let forced_miss = self
            .forced_test_misses
            .lock()
            .is_ok_and(|mut forced| forced.remove(agent_id.as_bytes()));
        let Ok(mut inner) = self.inner.lock() else {
            return (None, forced_miss);
        };
        if forced_miss {
            inner.remove(agent_id.as_bytes());
            return (None, true);
        }
        let Some(entry) = inner.get(agent_id.as_bytes()) else {
            return (None, false);
        };
        if now.duration_since(entry.seen_at) > self.ttl {
            inner.remove(agent_id.as_bytes());
            return (None, false);
        }
        (
            Some(CapabilityBinding {
                capabilities: entry.capabilities.clone(),
                machine_id: MachineId(entry.machine_id),
            }),
            false,
        )
    }

    /// Insert / refresh a cache entry.
    ///
    /// `created_at_unix_ms` is the advert's signed sender-side timestamp and
    /// orders adverts from the same sender: an advert strictly older than the
    /// cached one is ignored. Gossip (epidemic broadcast) does not guarantee
    /// in-order delivery, so without this a daemon's startup `pending`
    /// (gossip_inbox=false) advert can arrive *after* its upgraded
    /// gossip-ready advert and clobber it — leaving every sender on the
    /// silent raw-QUIC fallback (`advert_cache_unusable`) until the next
    /// republish window. An equal timestamp refreshes the TTL (duplicate
    /// delivery of the same advert).
    pub fn insert(
        &self,
        agent_id: AgentId,
        machine_id: MachineId,
        capabilities: DmCapabilities,
        created_at_unix_ms: u64,
    ) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        if let Some(existing) = inner.get(agent_id.as_bytes()) {
            if created_at_unix_ms < existing.created_at_unix_ms {
                return;
            }
        }
        inner.insert(
            *agent_id.as_bytes(),
            CachedAdvert {
                capabilities,
                machine_id: *machine_id.as_bytes(),
                seen_at: Instant::now(),
                created_at_unix_ms,
            },
        );
    }

    /// Insert capability material imported from an agent card unless it would
    /// lower the protocol version of a live runtime advert.
    ///
    /// Agent cards remain useful for first contact and refresh same-version
    /// KEM/machine material, but current cards advertise v1 even when the live
    /// daemon has published a signed v2 durable-ACK advert. Treating card import
    /// time as a fresher advert timestamp would otherwise replace that v2
    /// binding and make strict product sends fail until the next mesh refresh.
    /// Returns `true` when the card material was inserted.
    pub fn insert_from_card(
        &self,
        agent_id: AgentId,
        machine_id: MachineId,
        capabilities: DmCapabilities,
        imported_at_unix_ms: u64,
    ) -> bool {
        let now = Instant::now();
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        if let Some(existing) = inner.get(agent_id.as_bytes()) {
            let existing_is_live = now.duration_since(existing.seen_at) <= self.ttl;
            if existing_is_live
                && existing.capabilities.max_protocol_version > capabilities.max_protocol_version
            {
                return false;
            }
        }
        inner.insert(
            *agent_id.as_bytes(),
            CachedAdvert {
                capabilities,
                machine_id: *machine_id.as_bytes(),
                seen_at: now,
                created_at_unix_ms: imported_at_unix_ms,
            },
        );
        true
    }

    /// Arm one deterministic cache miss for an authenticated daemon test.
    ///
    /// The next lookup for `agent_id` removes any cached advert and returns
    /// `None`, regardless of intervening startup adverts. The hook is inert
    /// unless explicitly armed through the daemon's disabled-by-default test
    /// control. The bounded set prevents even an authenticated test client
    /// from growing process memory without limit.
    #[doc(hidden)]
    pub fn force_miss_once_for_testing(&self, agent_id: AgentId) -> bool {
        const MAX_FORCED_TEST_MISSES: usize = 256;
        let Ok(mut forced) = self.forced_test_misses.lock() else {
            return false;
        };
        if forced.len() >= MAX_FORCED_TEST_MISSES && !forced.contains(agent_id.as_bytes()) {
            return false;
        }
        forced.insert(*agent_id.as_bytes())
    }

    /// Current cache size (diagnostic).
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or_default()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Current unix-ms (convenience mirror of `dm::now_unix_ms` to keep this
/// module's dependencies narrow).
#[must_use]
pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_store_insert_and_lookup() {
        let store = CapabilityStore::new();
        let agent_id = AgentId([1u8; 32]);
        let machine_id = MachineId([2u8; 32]);
        let caps = DmCapabilities::v1_gossip_ready(vec![0u8; 1184]);
        assert!(store.lookup(&agent_id).is_none());
        store.insert(agent_id, machine_id, caps.clone(), 1_000);
        let got = store.lookup(&agent_id).expect("hit");
        assert_eq!(got.max_protocol_version, caps.max_protocol_version);
        assert_eq!(got.gossip_inbox, caps.gossip_inbox);
        let binding = store.lookup_binding(&agent_id).expect("bound hit");
        assert_eq!(binding.machine_id, machine_id);
        assert_eq!(
            binding.capabilities.max_protocol_version,
            caps.max_protocol_version
        );
    }

    #[test]
    fn forced_test_miss_survives_intervening_advert_then_consumes_once() {
        let store = CapabilityStore::new();
        let agent_id = AgentId([0x31; 32]);
        let machine_id = MachineId([0x42; 32]);
        let caps = DmCapabilities::v2_durable_gossip_ready(vec![0x53; 1184]);
        store.insert(agent_id, machine_id, caps.clone(), 1_000);
        assert!(store.force_miss_once_for_testing(agent_id));

        // A startup-burst advert racing between control arming and strict send
        // cannot defeat the deterministic next-lookup miss.
        store.insert(agent_id, machine_id, caps.clone(), 2_000);
        let (binding, forced_refresh) = store.lookup_binding_with_refresh_proof(&agent_id);
        assert!(binding.is_none());
        assert!(forced_refresh);
        store.insert(agent_id, machine_id, caps, 3_000);
        let (binding, forced_refresh) = store.lookup_binding_with_refresh_proof(&agent_id);
        assert!(
            binding.is_some(),
            "the forced miss must be consumed exactly once"
        );
        assert!(!forced_refresh);
    }

    /// Gossip delivers adverts out of order. A daemon publishes a `pending`
    /// (no gossip inbox) advert at startup and an upgraded gossip-ready one
    /// once its KEM key is wired; if the stale pending advert arrives last it
    /// must NOT clobber the ready one — that routes every DM to the silent
    /// raw-QUIC fallback and the recipient's app never sees them (the
    /// PR #100 dogfood group_join black-hole).
    #[test]
    fn capability_store_ignores_stale_out_of_order_advert() {
        let store = CapabilityStore::new();
        let agent_id = AgentId([5u8; 32]);
        let machine_id = MachineId([6u8; 32]);
        store.insert(
            agent_id,
            machine_id,
            DmCapabilities::v1_gossip_ready(vec![0u8; 1184]),
            2_000,
        );
        // Older pending advert delivered late: ignored.
        store.insert(agent_id, machine_id, DmCapabilities::pending(), 1_000);
        let got = store.lookup(&agent_id).expect("hit");
        assert!(
            got.gossip_inbox && !got.kem_public_key.is_empty(),
            "stale pending advert must not downgrade a usable cached advert"
        );
        // A genuinely fresher downgrade (e.g. daemon restarted pre-KEM) still
        // applies — ordering, not blanket downgrade protection.
        store.insert(agent_id, machine_id, DmCapabilities::pending(), 3_000);
        let got = store.lookup(&agent_id).expect("hit");
        assert!(
            !got.gossip_inbox,
            "fresher advert must win regardless of content"
        );
    }

    #[test]
    fn v1_card_cannot_downgrade_live_v2_runtime_binding() {
        let store = CapabilityStore::new();
        let agent_id = AgentId([0x71; 32]);
        let runtime_machine = MachineId([0x72; 32]);
        let runtime_key = vec![0x73; 1184];
        store.insert(
            agent_id,
            runtime_machine,
            DmCapabilities::v2_durable_gossip_ready(runtime_key.clone()),
            1_000,
        );

        assert!(!store.insert_from_card(
            agent_id,
            MachineId([0x74; 32]),
            DmCapabilities::v1_gossip_ready(vec![0x75; 1184]),
            2_000,
        ));

        let binding = store.lookup_binding(&agent_id).expect("runtime binding");
        assert_eq!(binding.machine_id, runtime_machine);
        assert!(binding.capabilities.supports_durable_app_ack());
        assert_eq!(binding.capabilities.kem_public_key, runtime_key);
    }

    #[test]
    fn repeated_v1_card_refreshes_card_capability_binding() {
        let store = CapabilityStore::new();
        let agent_id = AgentId([0x81; 32]);
        let first_machine = MachineId([0x82; 32]);
        let refreshed_machine = MachineId([0x83; 32]);
        assert!(store.insert_from_card(
            agent_id,
            first_machine,
            DmCapabilities::v1_gossip_ready(vec![0x84; 1184]),
            1_000,
        ));
        assert!(store.insert_from_card(
            agent_id,
            refreshed_machine,
            DmCapabilities::v1_gossip_ready(vec![0x85; 1184]),
            2_000,
        ));

        let binding = store
            .lookup_binding(&agent_id)
            .expect("refreshed card binding");
        assert_eq!(binding.machine_id, refreshed_machine);
        assert_eq!(binding.capabilities.max_protocol_version, 1);
        assert_eq!(binding.capabilities.kem_public_key, vec![0x85; 1184]);
    }

    #[test]
    fn capability_store_expires_on_ttl() {
        // Deterministic: insert records `seen_at ≈ now`, then the test
        // queries `lookup_at` at a synthetic future instant past the TTL.
        // No wall-clock sleep is involved, so CI scheduling jitter can never
        // push the "present" lookup past the TTL boundary — the prior flake.
        let ttl = Duration::from_secs(60);
        let store = CapabilityStore::with_ttl(ttl);
        let agent_id = AgentId([3u8; 32]);
        let machine_id = MachineId([4u8; 32]);
        store.insert(
            agent_id,
            machine_id,
            DmCapabilities::v1_gossip_ready(vec![0u8; 1184]),
            1_000,
        );
        // `seen_at` was captured inside `insert` just before this point, so a
        // lookup at "now" is well within the TTL.
        let now = Instant::now();
        assert!(
            store.lookup_at(&agent_id, now).is_some(),
            "entry must be present within the TTL"
        );
        // Advance a deterministic span past the TTL and re-query.
        let after_ttl = now + ttl + Duration::from_millis(1);
        assert!(
            store.lookup_at(&agent_id, after_ttl).is_none(),
            "entry must be evicted once the TTL elapses"
        );
    }

    #[test]
    fn advert_signed_bytes_deterministic() {
        let advert = CapabilityAdvert {
            protocol_version: 1,
            agent_id: [7u8; 32],
            machine_id: [8u8; 32],
            created_at_unix_ms: 1_234_567_890_000,
            capabilities: DmCapabilities::v1_gossip_ready(vec![0u8; 1184]),
            signature: vec![0u8; 64],
        };
        let a = advert.signed_bytes().expect("signed bytes");
        let b = advert.signed_bytes().expect("signed bytes 2");
        assert_eq!(a, b);
        assert!(a.starts_with(ADVERT_SIGN_DOMAIN));
    }
}
