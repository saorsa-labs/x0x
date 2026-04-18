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
    ttl: Duration,
}

struct CachedAdvert {
    capabilities: DmCapabilities,
    _machine_id: [u8; 32],
    seen_at: Instant,
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
            ttl: Duration::from_secs(ADVERT_CACHE_TTL_SECS),
        }
    }

    /// Custom-TTL store (primarily for tests).
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Look up a peer's capability. Returns `None` if unknown or expired.
    pub fn lookup(&self, agent_id: &AgentId) -> Option<DmCapabilities> {
        let Ok(mut inner) = self.inner.lock() else {
            return None;
        };
        let now = Instant::now();
        let entry = inner.get(agent_id.as_bytes())?;
        if now.duration_since(entry.seen_at) > self.ttl {
            inner.remove(agent_id.as_bytes());
            return None;
        }
        Some(entry.capabilities.clone())
    }

    /// Insert / refresh a cache entry.
    pub fn insert(&self, agent_id: AgentId, machine_id: MachineId, capabilities: DmCapabilities) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        inner.insert(
            *agent_id.as_bytes(),
            CachedAdvert {
                capabilities,
                _machine_id: *machine_id.as_bytes(),
                seen_at: Instant::now(),
            },
        );
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
        store.insert(agent_id, machine_id, caps.clone());
        let got = store.lookup(&agent_id).expect("hit");
        assert_eq!(got.max_protocol_version, caps.max_protocol_version);
        assert_eq!(got.gossip_inbox, caps.gossip_inbox);
    }

    #[test]
    fn capability_store_expires_on_ttl() {
        let store = CapabilityStore::with_ttl(Duration::from_millis(50));
        let agent_id = AgentId([3u8; 32]);
        let machine_id = MachineId([4u8; 32]);
        store.insert(
            agent_id,
            machine_id,
            DmCapabilities::v1_gossip_ready(vec![0u8; 1184]),
        );
        assert!(store.lookup(&agent_id).is_some());
        std::thread::sleep(Duration::from_millis(100));
        assert!(store.lookup(&agent_id).is_none());
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
