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

/// Side-channel on which a strict (ADR 0030) sender asks one specific peer to
/// republish its signed capability advert.
///
/// Adverts normally refresh only every five minutes, which is far longer than
/// a product send can wait. Requests travel in authenticated pub/sub
/// envelopes and responders still build and sign a fresh advert, so this
/// channel grants no capability and cannot weaken the advert's
/// AgentId + MachineId binding.
pub const DM_CAPABILITY_TARGETED_REQUEST_TOPIC: &str = "x0x/caps/v1/request/targeted-v2";

/// Dedicated response topic for a targeted refresh. The steady advert topic is
/// Bulk anti-entropy traffic; a strict send has only a short convergence
/// window, so its request and signed response use their own Critical control
/// topics rather than being cooled behind the fleet-wide advert stream.
pub const DM_CAPABILITY_TARGETED_RESPONSE_TOPIC: &str = "x0x/caps/v1/response/targeted-v2";

/// Domain-separation prefix for the advert signature bytes.
const ADVERT_SIGN_DOMAIN: &[u8] = b"x0x-caps-v1";

/// Cadence at which agents republish their advert. Kept in step with
/// `IDENTITY_HEARTBEAT_INTERVAL_SECS` (10 min): idle-network broadcast cost
/// scales linearly with cadence, and the 900 s cache TTL still tolerates a
/// missed window only for sub-TTL intervals, so this must stay < 900 s.
pub const ADVERT_PUBLISH_INTERVAL_SECS: u64 = 600;

/// How long a cached advert remains usable before it's considered stale.
/// Must be > `ADVERT_PUBLISH_INTERVAL_SECS` so that a single missed
/// publish window doesn't evict the cache entry.
pub const ADVERT_CACHE_TTL_SECS: u64 = 900;

/// Maximum tolerated sender clock lead for signed capability state. An advert
/// dated further ahead than this is rejected rather than cached, so a skewed
/// or hostile clock cannot mint an entry that outlives the local TTL.
pub const MAX_CAPABILITY_FUTURE_SKEW_SECS: u64 = 300;

fn timestamp_is_fresh_for_ttl(created_at_unix_ms: u64, now_unix_ms: u64, ttl_ms: u64) -> bool {
    let skew_ms = MAX_CAPABILITY_FUTURE_SKEW_SECS.saturating_mul(1_000);
    ttl_ms > 0
        && created_at_unix_ms <= now_unix_ms.saturating_add(skew_ms)
        && now_unix_ms.saturating_sub(created_at_unix_ms) < ttl_ms
}

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

/// Legacy (pre-#437) wire shape of [`dm::DmCapabilities`] — the exact
/// five-field sequence old peers advertise (no `digest_support`).
/// Postcard is positional and the caps sit **inside** the advert before
/// `signature`, so a naive single-struct decode would misparse the
/// digest bit from the signature's length bytes; this mirror preserves
/// the old byte layout for the two-stage decode below.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DmCapabilitiesV1Wire {
    max_protocol_version: u16,
    gossip_inbox: bool,
    kem_algorithm: String,
    max_envelope_bytes: usize,
    #[serde(default)]
    kem_public_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CapabilityAdvertV1Wire {
    protocol_version: u16,
    agent_id: [u8; 32],
    machine_id: [u8; 32],
    created_at_unix_ms: u64,
    capabilities: DmCapabilitiesV1Wire,
    signature: Vec<u8>,
}

impl CapabilityAdvert {
    /// Two-stage postcard decode for the #437 `digest_support`
    /// transition: the v2 shape (caps may carry `digest_support`) first,
    /// then the byte-exact v1 legacy shape, lifted with
    /// `digest_support: false`. Signature verification works for both:
    /// `verify_advert_signature` re-serializes the decoded struct, and a
    /// false `digest_support` is omitted from serialization
    /// (`skip_serializing_if`), so a v1-decoded advert re-encodes
    /// byte-identically to what its signer signed.
    ///
    /// # Errors
    ///
    /// Returns the v2 decode error when the bytes parse as neither shape.
    pub fn from_postcard(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes::<Self>(bytes).or_else(|_| {
            postcard::from_bytes::<CapabilityAdvertV1Wire>(bytes).map(|v1| Self {
                protocol_version: v1.protocol_version,
                agent_id: v1.agent_id,
                machine_id: v1.machine_id,
                created_at_unix_ms: v1.created_at_unix_ms,
                capabilities: crate::dm::DmCapabilities {
                    max_protocol_version: v1.capabilities.max_protocol_version,
                    gossip_inbox: v1.capabilities.gossip_inbox,
                    kem_algorithm: v1.capabilities.kem_algorithm,
                    max_envelope_bytes: v1.capabilities.max_envelope_bytes,
                    kem_public_key: v1.capabilities.kem_public_key,
                    digest_support: false,
                },
                signature: v1.signature,
            })
        })
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
    machine_id: [u8; 32],
    expires_at: Instant,
    created_at_unix_ms: u64,
}

/// TTL-validated capability material together with the machine binding signed
/// into the same advert.
///
/// Strict (ADR 0030) sends pin the ACK waiter to this exact machine, so the
/// two must travel together — a capability without its machine cannot satisfy
/// the durable gate.
#[derive(Debug, Clone)]
pub struct CapabilityBinding {
    /// The advertised capabilities.
    pub capabilities: DmCapabilities,
    /// The machine that signed the advert carrying `capabilities`.
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
        self.lookup_binding(agent_id)
            .map(|binding| binding.capabilities)
    }

    /// Look up a peer's capability together with the machine that signed it.
    pub fn lookup_binding(&self, agent_id: &AgentId) -> Option<CapabilityBinding> {
        self.lookup_binding_at(agent_id, Instant::now())
    }

    /// Testable clock seam for [`Self::lookup_binding`].
    pub fn lookup_binding_at(&self, agent_id: &AgentId, now: Instant) -> Option<CapabilityBinding> {
        let Ok(mut inner) = self.inner.lock() else {
            return None;
        };
        let entry = inner.get(agent_id.as_bytes())?;
        if now > entry.expires_at {
            inner.remove(agent_id.as_bytes());
            return None;
        }
        Some(CapabilityBinding {
            capabilities: entry.capabilities.clone(),
            machine_id: MachineId(entry.machine_id),
        })
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

    /// Insert / refresh a cache entry.
    ///
    /// `created_at_unix_ms` is the advert's signed sender-side timestamp and
    /// orders adverts from the same sender: an advert strictly older than the
    /// cached one is ignored. Gossip (epidemic broadcast) does not guarantee
    /// in-order delivery, so without this a daemon's startup `pending`
    /// (gossip_inbox=false) advert can arrive *after* its upgraded
    /// gossip-ready advert and clobber it — leaving every sender on the
    /// silent raw-QUIC fallback (`advert_cache_unusable`) until the next
    /// republish window. An equal timestamp is a replay and cannot extend the
    /// original expiry.
    ///
    /// Entry lifetime is derived from the *signed* timestamp, not from arrival
    /// time: a replayed advert therefore ages out on its own schedule instead
    /// of being renewed indefinitely by whoever rebroadcasts it.
    ///
    /// Returns `true` only when fresh signed state was inserted.
    pub fn insert(
        &self,
        agent_id: AgentId,
        machine_id: MachineId,
        capabilities: DmCapabilities,
        created_at_unix_ms: u64,
    ) -> bool {
        let Some(expires_at) = self.expiry_for_signed_timestamp(created_at_unix_ms, now_unix_ms())
        else {
            return false;
        };
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        if let Some(existing) = inner.get(agent_id.as_bytes()) {
            if created_at_unix_ms <= existing.created_at_unix_ms {
                return false;
            }
        }
        inner.insert(
            *agent_id.as_bytes(),
            CachedAdvert {
                capabilities,
                machine_id: *machine_id.as_bytes(),
                expires_at,
                created_at_unix_ms,
            },
        );
        true
    }

    /// Insert capability material imported from an agent card, unless doing so
    /// would lower the protocol version of a live runtime advert.
    ///
    /// Cards remain useful for first contact and for refreshing same-version
    /// KEM/machine material. But a live daemon publishes its current runtime
    /// capability on the mesh, while a legacy or statically exported card may
    /// still claim v1 — and ADR 0030 §3 forbids an unsigned/stale source from
    /// lowering a live binding, which would make strict sends fail until the
    /// next mesh refresh.
    ///
    /// Returns `true` when the card material was inserted.
    pub fn insert_from_card(
        &self,
        agent_id: AgentId,
        machine_id: MachineId,
        capabilities: DmCapabilities,
        created_at_unix_ms: u64,
    ) -> bool {
        let now = Instant::now();
        let Some(expires_at) =
            self.expiry_for_signed_timestamp_at(created_at_unix_ms, now_unix_ms(), now)
        else {
            return false;
        };
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        if let Some(existing) = inner.get(agent_id.as_bytes()) {
            if created_at_unix_ms < existing.created_at_unix_ms {
                return false;
            }
            if now <= existing.expires_at
                && existing.capabilities.max_protocol_version > capabilities.max_protocol_version
            {
                return false;
            }
            if created_at_unix_ms == existing.created_at_unix_ms {
                let material_is_identical = existing.machine_id == *machine_id.as_bytes()
                    && existing.capabilities == capabilities;
                if !material_is_identical {
                    // Card timestamps have second precision. Two differently
                    // signed cards from the same second cannot be ordered, so
                    // fail closed rather than retain a possibly dead KEM key
                    // or guess that the import is newer. A runtime advert has
                    // millisecond precision and can install the unambiguous
                    // current binding.
                    inner.remove(agent_id.as_bytes());
                }
                return false;
            }
        }
        inner.insert(
            *agent_id.as_bytes(),
            CachedAdvert {
                capabilities,
                machine_id: *machine_id.as_bytes(),
                expires_at,
                created_at_unix_ms,
            },
        );
        true
    }

    fn expiry_for_signed_timestamp(
        &self,
        created_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Option<Instant> {
        self.expiry_for_signed_timestamp_at(created_at_unix_ms, now_unix_ms, Instant::now())
    }

    fn expiry_for_signed_timestamp_at(
        &self,
        created_at_unix_ms: u64,
        now_unix_ms: u64,
        now: Instant,
    ) -> Option<Instant> {
        let ttl_ms = u64::try_from(self.ttl.as_millis()).unwrap_or(u64::MAX);
        if !timestamp_is_fresh_for_ttl(created_at_unix_ms, now_unix_ms, ttl_ms) {
            return None;
        }
        let remaining_ms = created_at_unix_ms
            .saturating_add(ttl_ms)
            .saturating_sub(now_unix_ms)
            // A tolerated future clock must not buy TTL + skew: every accepted
            // record expires no later than one local TTL from insertion.
            .min(ttl_ms);
        now.checked_add(Duration::from_millis(remaining_ms))
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
        assert!(store.insert(agent_id, machine_id, caps.clone(), now_unix_ms()));
        let got = store.lookup(&agent_id).expect("hit");
        assert_eq!(got.max_protocol_version, caps.max_protocol_version);
        assert_eq!(got.gossip_inbox, caps.gossip_inbox);
        let binding = store.lookup_binding(&agent_id).expect("bound hit");
        assert_eq!(binding.machine_id, machine_id);
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
        let issued_at = now_unix_ms();
        assert!(store.insert(
            agent_id,
            machine_id,
            DmCapabilities::v1_gossip_ready(vec![0u8; 1184]),
            issued_at + 1,
        ));
        // Older pending advert delivered late: ignored.
        assert!(!store.insert(agent_id, machine_id, DmCapabilities::pending(), issued_at));
        let got = store.lookup(&agent_id).expect("hit");
        assert!(
            got.gossip_inbox && !got.kem_public_key.is_empty(),
            "stale pending advert must not downgrade a usable cached advert"
        );
        // A genuinely fresher downgrade (e.g. daemon restarted pre-KEM) still
        // applies — ordering, not blanket downgrade protection.
        assert!(store.insert(
            agent_id,
            machine_id,
            DmCapabilities::pending(),
            issued_at + 2
        ));
        let got = store.lookup(&agent_id).expect("hit");
        assert!(
            !got.gossip_inbox,
            "fresher advert must win regardless of content"
        );
    }

    #[test]
    fn capability_store_expires_on_ttl() {
        // Deterministic: insert derives `expires_at` from the signed
        // timestamp, then the test queries `lookup_at` at a synthetic future
        // instant past the TTL. No wall-clock sleep is involved, so CI
        // scheduling jitter can never push the "present" lookup past the TTL
        // boundary — the prior flake.
        let ttl = Duration::from_secs(60);
        let store = CapabilityStore::with_ttl(ttl);
        let agent_id = AgentId([3u8; 32]);
        let machine_id = MachineId([4u8; 32]);
        assert!(store.insert(
            agent_id,
            machine_id,
            DmCapabilities::v1_gossip_ready(vec![0u8; 1184]),
            now_unix_ms(),
        ));
        // The signed timestamp was captured immediately before insertion, so
        // a lookup at "now" is well within the TTL.
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

    /// ADR 0030 §3: "a live binding's version is never lowered by an unsigned
    /// source". A legacy card claiming v1 must not quarantine the live v2
    /// advert, or every strict send to that peer 409s until the next mesh
    /// refresh.
    #[test]
    fn v1_card_cannot_downgrade_a_live_v2_runtime_binding() {
        let store = CapabilityStore::new();
        let agent_id = AgentId([0x71; 32]);
        let runtime_machine = MachineId([0x72; 32]);
        let runtime_key = vec![0x73; 1184];
        let issued_at = now_unix_ms();
        assert!(store.insert(
            agent_id,
            runtime_machine,
            DmCapabilities::v2_durable_gossip_ready(runtime_key.clone()),
            issued_at,
        ));

        assert!(!store.insert_from_card(
            agent_id,
            MachineId([0x74; 32]),
            DmCapabilities::v1_gossip_ready(vec![0x75; 1184]),
            issued_at + 1,
        ));

        let binding = store.lookup_binding(&agent_id).expect("runtime binding");
        assert_eq!(binding.machine_id, runtime_machine);
        assert!(binding.capabilities.supports_durable_app_ack());
        assert_eq!(binding.capabilities.kem_public_key, runtime_key);
    }

    /// Same-version card imports are still the first-contact path, so a newer
    /// card must refresh the machine + KEM material it carries.
    #[test]
    fn newer_same_version_card_refreshes_the_binding() {
        let store = CapabilityStore::new();
        let agent_id = AgentId([0x81; 32]);
        let refreshed_machine = MachineId([0x83; 32]);
        let issued_at = now_unix_ms();
        assert!(store.insert_from_card(
            agent_id,
            MachineId([0x82; 32]),
            DmCapabilities::v1_gossip_ready(vec![0x84; 1184]),
            issued_at,
        ));
        assert!(store.insert_from_card(
            agent_id,
            refreshed_machine,
            DmCapabilities::v1_gossip_ready(vec![0x85; 1184]),
            issued_at + 1,
        ));

        let binding = store
            .lookup_binding(&agent_id)
            .expect("refreshed card binding");
        assert_eq!(binding.machine_id, refreshed_machine);
        assert_eq!(binding.capabilities.max_protocol_version, 1);
        assert_eq!(binding.capabilities.kem_public_key, vec![0x85; 1184]);
    }

    /// Card timestamps have second precision, so two differently signed cards
    /// from the same second cannot be ordered. Retaining either one risks
    /// pinning a dead KEM key, so the ambiguous entry is dropped and only a
    /// millisecond-precision runtime advert can reinstate a binding.
    #[test]
    fn conflicting_same_timestamp_cards_quarantine_until_a_fresh_advert() {
        let store = CapabilityStore::new();
        let agent = AgentId([0xB1; 32]);
        let machine_a = MachineId([0xB2; 32]);
        let machine_b = MachineId([0xB3; 32]);
        let kem_b = vec![0xB5; 1184];
        let card_created_at_ms = now_unix_ms();

        assert!(store.insert_from_card(
            agent,
            machine_a,
            DmCapabilities::v1_gossip_ready(vec![0xB4; 1184]),
            card_created_at_ms,
        ));
        assert!(!store.insert_from_card(
            agent,
            machine_b,
            DmCapabilities::v1_gossip_ready(kem_b.clone()),
            card_created_at_ms,
        ));
        assert!(
            store.lookup_binding(&agent).is_none(),
            "an ambiguous same-second restart must not retain the dead A binding"
        );

        assert!(store.insert(
            agent,
            machine_b,
            DmCapabilities::v2_durable_gossip_ready(kem_b.clone()),
            card_created_at_ms + 1,
        ));
        let binding = store.lookup_binding(&agent).expect("fresh B binding");
        assert_eq!(binding.machine_id, machine_b);
        assert_eq!(binding.capabilities.kem_public_key, kem_b);
    }

    /// Expiry follows the *signed* timestamp. A replayed advert must neither
    /// be accepted nor renew the original entry's lifetime, and a future-dated
    /// one must not buy more than one local TTL.
    #[test]
    fn signed_time_window_rejects_stale_future_and_replayed_adverts() {
        let ttl = Duration::from_secs(60);
        let store = CapabilityStore::with_ttl(ttl);
        let now_ms = now_unix_ms();
        let agent = AgentId([0x91; 32]);
        let first_machine = MachineId([0x92; 32]);
        let caps = DmCapabilities::v2_durable_gossip_ready(vec![0x94; 1184]);

        // Older than the TTL, and further ahead than the tolerated skew.
        assert!(!store.insert(agent, first_machine, caps.clone(), now_ms - 61_000));
        assert!(!store.insert(
            agent,
            first_machine,
            caps.clone(),
            now_ms + MAX_CAPABILITY_FUTURE_SKEW_SECS * 1_000 + 1_000,
        ));
        assert!(store.lookup_binding(&agent).is_none());

        let issued_at = now_ms - 59_000;
        assert!(store.insert(agent, first_machine, caps.clone(), issued_at));
        // Replay of the same signed advert from a different machine: rejected.
        assert!(!store.insert(agent, MachineId([0x93; 32]), caps, issued_at));
        let retained = store.lookup_binding(&agent).expect("original binding");
        assert_eq!(retained.machine_id, first_machine);
        // The replay did not extend the original expiry, which is ~1s away.
        let after_original_expiry = Instant::now() + Duration::from_millis(1_100);
        assert!(store
            .lookup_binding_at(&agent, after_original_expiry)
            .is_none());
    }

    /// A tolerated future clock must not extend an entry past one local TTL.
    #[test]
    fn future_dated_advert_expires_within_one_local_ttl() {
        let ttl = Duration::from_secs(1);
        let store = CapabilityStore::with_ttl(ttl);
        let agent = AgentId([0xA1; 32]);
        let future_issued_at = now_unix_ms() + MAX_CAPABILITY_FUTURE_SKEW_SECS * 1_000;

        assert!(store.insert(
            agent,
            MachineId([0xA2; 32]),
            DmCapabilities::v2_durable_gossip_ready(vec![0xA3; 1184]),
            future_issued_at,
        ));
        assert!(
            store.lookup_binding(&agent).is_some(),
            "a successful insert must be immediately observable"
        );
        let after_local_ttl = Instant::now() + ttl + Duration::from_millis(1);
        assert!(
            store.lookup_binding_at(&agent, after_local_ttl).is_none(),
            "future clock skew must not extend a one-second local TTL"
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

    #[test]
    fn false_digest_support_encodes_byte_identical_to_v1_caps() {
        // Why (#437 round 4): `digest_support: false` must serialize to
        // the EXACT pre-#437 caps bytes (skip-when-false), so old peers
        // that never learn about the bit keep verifying our adverts and
        // cards unchanged.
        let mut caps = DmCapabilities::v1_gossip_ready(vec![5u8; 16]);
        caps.digest_support = false;
        let v1_caps = DmCapabilitiesV1Wire {
            max_protocol_version: caps.max_protocol_version,
            gossip_inbox: caps.gossip_inbox,
            kem_algorithm: caps.kem_algorithm.clone(),
            max_envelope_bytes: caps.max_envelope_bytes,
            kem_public_key: caps.kem_public_key.clone(),
        };
        assert_eq!(
            postcard::to_allocvec(&caps).expect("v2-false encode"),
            postcard::to_allocvec(&v1_caps).expect("v1 encode"),
            "a false digest_support bit must be wire-invisible"
        );

        // True appends exactly one byte.
        caps.digest_support = true;
        let enc_true = postcard::to_allocvec(&caps).expect("v2-true encode");
        let enc_false = {
            caps.digest_support = false;
            postcard::to_allocvec(&caps).expect("v2-false encode")
        };
        assert_eq!(enc_true.len(), enc_false.len() + 1);
        assert!(enc_true.starts_with(&enc_false));
    }

    #[test]
    fn legacy_advert_decodes_and_verifies_on_new_node() {
        // Why (#437 round 4): new nodes must keep reading OLD peers'
        // adverts — the caps struct sits before `signature` in the
        // positional encoding, so a naive v2-only decode misparses. The
        // two-stage decode recovers the v1 shape, and because a
        // v1-decoded advert has digest_support=false (omitted on
        // re-serialize), signature verification still passes against
        // the signer's original bytes.
        use crate::gossip::SigningContext;
        use crate::identity::AgentKeypair;

        let kp = AgentKeypair::generate().expect("keypair");
        let signing = SigningContext::from_keypair(&kp);
        let v1_caps = DmCapabilitiesV1Wire {
            max_protocol_version: 1,
            gossip_inbox: true,
            kem_algorithm: "ML-KEM-768".to_string(),
            max_envelope_bytes: crate::dm::MAX_ENVELOPE_BYTES,
            kem_public_key: vec![7u8; 16],
        };
        let mut v1 = CapabilityAdvertV1Wire {
            protocol_version: 1,
            agent_id: *signing.agent_id.as_bytes(),
            machine_id: [9u8; 32],
            created_at_unix_ms: 1_700_000_000_000,
            capabilities: v1_caps,
            signature: Vec::new(),
        };
        // Sign over the v1 signed-bytes shape (what an old node computed).
        let mut sign_buf = Vec::new();
        sign_buf.extend_from_slice(ADVERT_SIGN_DOMAIN);
        sign_buf.extend_from_slice(&v1.protocol_version.to_be_bytes());
        sign_buf.extend_from_slice(&v1.agent_id);
        sign_buf.extend_from_slice(&v1.machine_id);
        sign_buf.extend_from_slice(&v1.created_at_unix_ms.to_be_bytes());
        sign_buf.extend_from_slice(&postcard::to_stdvec(&v1.capabilities).expect("caps"));
        v1.signature = signing.sign(&sign_buf).expect("sign v1 advert");

        let wire = postcard::to_allocvec(&v1).expect("v1 advert encode");
        // The v2 struct alone must fail (positional)...
        assert!(postcard::from_bytes::<CapabilityAdvert>(&wire).is_err());
        // ...the two-stage decode recovers it, unbound...
        let decoded = CapabilityAdvert::from_postcard(&wire).expect("two-stage decode");
        assert!(!decoded.capabilities.digest_support);
        // ...and it still verifies (re-serialization omits the false bit).
        assert!(crate::dm_capability_service::verify_advert_signature(
            &decoded,
            &signing.public_key_bytes
        ));
    }
}
