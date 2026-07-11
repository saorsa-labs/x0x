//! X0X-0070 — application-level peer relay (Tailscale-style).
//!
//! Tailscale and iroh both report ~10% of cross-region peer pairs need
//! a relay fallback when direct NAT traversal fails. x0x's 4 h soaks
//! show 7–17% pair failure on the longest cross-region paths
//! (`command_dispatch_fail` to sfo / nuremberg / singapore) — and we
//! have had **no** relay fallback. This module is that fallback.
//!
//! ## Mechanism
//!
//! When a direct DM to peer `P` fails `fail_threshold` times within
//! `fail_window`, `P` is marked `needs_relay`. The sender then picks a
//! relay candidate `R` and wraps the (already end-to-end encrypted and
//! origin-signed) `DmEnvelope` inside a `RelayedDm`:
//!
//! ```text
//! RelayedDm { header: RelayHeader { dst, sender, originated_at, sig },
//!             inner:  DmEnvelope (opaque — e2e encrypted, origin-signed) }
//! ```
//!
//! `R` verifies the `RelayHeader` signature (proves the relay request
//! genuinely came from `sender`), confirms it is itself only being
//! asked to forward — not to be the final recipient — and sends
//! `inner` **directly** to `dst`. There is no re-wrapping: a relay
//! forwards the plain inner envelope, so a relay-of-a-relay is
//! structurally impossible (the `inner` field is typed `DmEnvelope`,
//! never `RelayedDm`).
//!
//! ## Security
//!
//! - The inner `DmEnvelope` keeps its X0X-0060 ACK-v2 + MLS
//!   end-to-end encryption and origin ML-DSA-65 signature intact. The
//!   relay `R` sees only the routing header — never the plaintext.
//! - The `RelayHeader` is independently signed by the sender's
//!   ML-DSA-65 agent key over domain-separated bytes, so `R` cannot be
//!   tricked into relaying for a forged origin, and a tampered
//!   `dst` / `originated_at` is rejected.
//! - One hop only — structurally enforced by the type system.
//! - **Forward-path hardening (#193).** Even with `enabled = true`, the
//!   forward arm is not an open relay by default: `require_contact_to_relay`
//!   (default `true`) refuses to forward on behalf of any sender not in
//!   the local contact store, and per-sender / global forward-rate and
//!   bandwidth caps bound the uplink an opted-in relay will spend. The
//!   contact gate applies only to the forward arm — a relayed DM
//!   addressed to this node is still received. See `RelayPolicy` and
//!   `RelayRefusal` for the knobs and refusal reasons.
//!
//! ## Status
//!
//! The primitives, telemetry, **and** runtime wiring all ship here: the
//! `RelayedDm` / `RelayHeader` wire types, signed-bytes construction +
//! verification, the `PeerRelay` engine (per-peer failure tracking,
//! `needs_relay` decision, relay-candidate selection), the `RelayStats`
//! counters, the fallback path in `Agent::send_direct_with_config`, and
//! the inbound receiver in `NetworkNode` (X0X-0070b, shipped). The #193
//! contact gate is enforced in [`crate::peer_relay::PeerRelay::disposition_for`];
//! rate and bandwidth admission is enforced by
//! [`crate::peer_relay::PeerRelay::reserve_forward`]. A
//! reservation charges quotas only when its send succeeds and releases its
//! capacity automatically on every failed or abandoned forward. The
//! [`crate::peer_relay::RelayPolicy`] is **disabled by default** — the relay path only engages
//! when a runtime explicitly enables it.
//!
//! Reference: Tailscale Peer Relays beta
//! <https://tailscale.com/blog/peer-relays-beta>; iroh DERP
//! <https://www.iroh.computer/blog/what-is-derp>.

use crate::dm::DmEnvelope;
use crate::identity::AgentId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Domain-separation prefix for the `RelayHeader` signature bytes.
const RELAY_HEADER_SIGN_DOMAIN: &[u8] = b"x0x-relay-hdr-v1";

/// Default number of consecutive direct-DM failures, within
/// [`RelayPolicy::fail_window`], before a peer is marked `needs_relay`.
pub const DEFAULT_FAIL_THRESHOLD: u32 = 3;

/// Default sliding window for the failure count.
pub const DEFAULT_FAIL_WINDOW: Duration = Duration::from_secs(60);

/// Default freshness budget for a relayed envelope. A relay drops a
/// `RelayedDm` whose `originated_at_unix_ms` is older than this — it
/// stops a captured relay envelope being replayed long after the fact.
pub const DEFAULT_RELAY_FRESHNESS: Duration = Duration::from_secs(30);

/// Clock-skew tolerance for a relayed envelope's `originated_at_unix_ms`.
/// A header whose timestamp is more than this far *ahead* of local
/// wall-clock is refused as stale — without this bound a far-future
/// timestamp would read as age 0 forever (replayable until the local
/// clock catches up). Mirrors `dm::CLOCK_SKEW_TOLERANCE_MS`.
pub const RELAY_CLOCK_SKEW_TOLERANCE_MS: u64 = 30_000;

/// Default sliding window for per-sender / global relay-forward rate and
/// bandwidth accounting (#193). Mirrors the failure-tracking window's
/// order of magnitude so an operator's mental model of "one minute" is
/// consistent across the engine.
pub const DEFAULT_RELAY_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Smallest supported rate/bandwidth accounting window. Zero-duration
/// windows would prune every committed charge immediately and silently
/// disable all relay caps, so policy construction and runtime admission both
/// clamp to this positive boundary.
pub const MIN_RELAY_LIMIT_WINDOW: Duration = Duration::from_millis(1);

/// Default cap on forwards a single sender may request within
/// [`DEFAULT_RELAY_LIMIT_WINDOW`] before being throttled. Generous for a
/// legitimate fallback path (which fires rarely) but stops a single
/// stranger from saturating an opted-in relay.
pub const DEFAULT_MAX_FORWARDS_PER_SENDER: u32 = 10;

/// Default cap on *total* forwards (all senders combined) within
/// [`DEFAULT_RELAY_LIMIT_WINDOW`] — the global concurrent-forward budget.
pub const DEFAULT_MAX_TOTAL_FORWARDS: u32 = 100;

/// Default cap on total forwarded bytes within
/// [`DEFAULT_RELAY_LIMIT_WINDOW`] (~1 MiB/min). Bounds the relay's uplink
/// spend so an opted-in relay cannot be drained for amplification.
pub const DEFAULT_MAX_FORWARD_BYTES_PER_WINDOW: u64 = 1024 * 1024;

/// Routing header for a relayed DM — the **only** part a relay node
/// sees in cleartext. Independently signed by the sender so the relay
/// can prove the request's origin and reject tampered routing fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayHeader {
    /// Wire-format version. Relays reject headers they can't parse.
    pub version: u16,
    /// Final recipient's `AgentId` (32-byte SHA-256 of ML-DSA-65 pubkey).
    pub dst_agent_id: [u8; 32],
    /// Origin sender's `AgentId`. The signature is verified against
    /// this agent's ML-DSA-65 public key.
    pub sender_agent_id: [u8; 32],
    /// Sender's ML-DSA-65 public key bytes — lets the relay verify the
    /// signature without a prior key exchange.
    pub sender_public_key: Vec<u8>,
    /// Sender-local unix-ms timestamp at relay-envelope creation. Used
    /// for the freshness check.
    pub originated_at_unix_ms: u64,
    /// ML-DSA-65 signature over the domain-separated header bytes
    /// (everything above, see [`RelayHeader::signing_bytes`]).
    pub signature: Vec<u8>,
}

impl RelayHeader {
    /// Current wire-format version.
    pub const VERSION: u16 = 1;

    /// Build the domain-separated bytes the sender signs / the relay
    /// verifies. Format:
    /// `RELAY_HEADER_SIGN_DOMAIN || version || dst_agent_id ||
    ///  sender_agent_id || sender_public_key || originated_at_unix_ms`.
    #[must_use]
    pub fn signing_bytes(
        version: u16,
        dst_agent_id: &[u8; 32],
        sender_agent_id: &[u8; 32],
        sender_public_key: &[u8],
        originated_at_unix_ms: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            RELAY_HEADER_SIGN_DOMAIN.len() + 2 + 32 + 32 + sender_public_key.len() + 8,
        );
        out.extend_from_slice(RELAY_HEADER_SIGN_DOMAIN);
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(dst_agent_id);
        out.extend_from_slice(sender_agent_id);
        out.extend_from_slice(sender_public_key);
        out.extend_from_slice(&originated_at_unix_ms.to_be_bytes());
        out
    }

    /// The signing bytes for *this* header instance.
    #[must_use]
    pub fn own_signing_bytes(&self) -> Vec<u8> {
        Self::signing_bytes(
            self.version,
            &self.dst_agent_id,
            &self.sender_agent_id,
            &self.sender_public_key,
            self.originated_at_unix_ms,
        )
    }

    /// Verify the header's self-consistency and signature:
    /// 1. `version` is recognised,
    /// 2. `sender_public_key` derives to `sender_agent_id`,
    /// 3. the ML-DSA-65 `signature` is valid over the signing bytes.
    ///
    /// Returns `true` only when all three hold. Does **not** check
    /// freshness or whether *we* are the intended relay — those are the
    /// caller's job (see [`PeerRelay::disposition_for`]).
    #[must_use]
    pub fn verify(&self) -> bool {
        if self.version != Self::VERSION {
            return false;
        }
        let public_key = match ant_quic::MlDsaPublicKey::from_bytes(&self.sender_public_key) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        // The embedded sender_agent_id must derive from the embedded
        // public key — otherwise a relay could be fooled into attributing
        // the request to a forged origin.
        let derived = AgentId::from_public_key(&public_key);
        if derived.0 != self.sender_agent_id {
            return false;
        }
        let signature = match ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(
            &self.signature,
        ) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
            &public_key,
            &self.own_signing_bytes(),
            &signature,
        )
        .is_ok()
    }
}

/// A DM being routed through a relay: the cleartext [`RelayHeader`]
/// plus the opaque, end-to-end-encrypted, origin-signed inner
/// [`DmEnvelope`]. The relay forwards `inner` verbatim — it is never
/// re-wrapped, so relay-of-a-relay is structurally impossible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayedDm {
    /// Routing + authentication header — the only part the relay reads.
    pub header: RelayHeader,
    /// The original DM envelope, opaque to the relay (still e2e
    /// encrypted and signed by the origin agent).
    pub inner: DmEnvelope,
}

/// What a relay node should do with an inbound [`RelayedDm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayDisposition {
    /// We are the final recipient — unwrap `inner` and deliver it
    /// through the normal inbound DM pipeline.
    DeliverLocally,
    /// We are an intermediate relay — forward `inner` directly to
    /// `dst_agent_id`. One hop only; do not re-wrap.
    Forward { dst_agent_id: [u8; 32] },
    /// Refuse: the header failed verification, the envelope is stale,
    /// or this node is over its relay-load budget. The reason is in
    /// the variant payload for telemetry.
    Refuse(RelayRefusal),
}

/// Why a relay node refused to handle a [`RelayedDm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayRefusal {
    /// The [`RelayHeader`] signature or self-consistency check failed.
    BadSignature,
    /// `originated_at_unix_ms` is older than the freshness budget — a
    /// likely replay of a captured relay envelope.
    Stale,
    /// This node's relay path is disabled by policy.
    PolicyDisabled,
    /// The relay header's authenticated `sender_agent_id` is not an
    /// *explicitly-trusted* contact — i.e. no entry, or only an
    /// auto-discovered `Unknown` entry (#193). Only `Known`/`Trusted`
    /// contacts pass the gate, so a peer merely seen during discovery
    /// cannot spend the relay's uplink. Stops a stranger (or a
    /// discovery-only acquaintance) from being forwarded.
    NotAContact,
    /// The sender is an explicitly **blocked** contact (#193). A blocked
    /// peer is refused on the forward arm **unconditionally** — even when
    /// `require_contact_to_relay` is `false` (open relay) and even before
    /// the rate/bandwidth caps are consulted. The operator's blocklist
    /// always wins.
    Blocked,
    /// The sender (or the relay globally) has exceeded its per-window
    /// forward-rate budget (#193). Throttles a burst of relay requests.
    RateLimited,
    /// Forwarding this envelope would exceed the per-window bandwidth
    /// cap (#193). Bounds total uplink spend on the relay path.
    BandwidthExceeded,
}

/// Policy knobs for the peer-relay engine.
///
/// # Contact gate (`require_contact_to_relay`, default `true`)
///
/// When `enabled` is `true` **and** `require_contact_to_relay` is `true`
/// (the secure default), [`PeerRelay::disposition_for`] refuses to
/// *forward* on behalf of any sender whose authenticated
/// `sender_agent_id` is not in the local contact store —
/// [`RelayRefusal::NotAContact`]. This closes the open-relay surface
/// from issue #193: a stranger can no longer spend the relay's uplink by
/// self-keying a fresh header. The gate applies to the **forward** arm
/// only; a relayed DM addressed to this node (`DeliverLocally`) is still
/// received — receiving is not relaying. An operator who explicitly
/// wants an open relay (e.g. a public DERP) sets
/// `require_contact_to_relay = false`.
///
/// # Rate + bandwidth limits (default-on, #193)
///
/// Even with the contact gate on, a compromised contact could attempt to
/// drain the relay. The forward path is therefore bounded by three
/// per-`limit_window` caps, atomically enforced by
/// [`PeerRelay::reserve_forward`] after destination resolution and encoding
/// but before transmission:
/// - `max_forwards_per_sender` — per-sender forward rate
///   ([`RelayRefusal::RateLimited`]),
/// - `max_total_forwards` — global forward rate across all senders,
/// - `max_forward_bytes_per_window` — total forwarded bytes
///   ([`RelayRefusal::BandwidthExceeded`]).
///
/// These still apply when the contact gate is off, so an explicitly-open
/// relay is not unbounded.
#[derive(Debug, Clone, Copy)]
pub struct RelayPolicy {
    /// Master gate. **Default `false`** — the relay path only engages
    /// when a runtime explicitly opts in. With this `false`,
    /// [`PeerRelay::needs_relay`] always returns `false` and
    /// [`PeerRelay::disposition_for`] refuses inbound relayed DMs with
    /// [`RelayRefusal::PolicyDisabled`].
    pub enabled: bool,
    /// Consecutive direct-DM failures, within `fail_window`, before a
    /// peer is considered to need a relay.
    pub fail_threshold: u32,
    /// Sliding window over which `fail_threshold` is counted.
    pub fail_window: Duration,
    /// A relayed envelope older than this is refused as a likely
    /// replay.
    pub freshness: Duration,
    /// When `true` (the **secure default**), the forward arm refuses any
    /// relay request whose authenticated `sender_agent_id` is not a
    /// local contact. Set `false` only for an explicitly-open relay.
    pub require_contact_to_relay: bool,
    /// Max forwards a single sender may request within `limit_window`
    /// before being throttled with [`RelayRefusal::RateLimited`].
    pub max_forwards_per_sender: u32,
    /// Max *total* forwards (all senders combined) within `limit_window`.
    pub max_total_forwards: u32,
    /// Sliding window for the rate + bandwidth caps above.
    pub limit_window: Duration,
    /// Max total forwarded bytes within `limit_window` before refusals
    /// with [`RelayRefusal::BandwidthExceeded`].
    pub max_forward_bytes_per_window: u64,
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            fail_threshold: DEFAULT_FAIL_THRESHOLD,
            fail_window: DEFAULT_FAIL_WINDOW,
            freshness: DEFAULT_RELAY_FRESHNESS,
            // Secure defaults (#193): the contact gate is ON and the
            // rate/bandwidth caps are populated. They are inert while
            // `enabled` is false.
            require_contact_to_relay: true,
            max_forwards_per_sender: DEFAULT_MAX_FORWARDS_PER_SENDER,
            max_total_forwards: DEFAULT_MAX_TOTAL_FORWARDS,
            limit_window: DEFAULT_RELAY_LIMIT_WINDOW,
            max_forward_bytes_per_window: DEFAULT_MAX_FORWARD_BYTES_PER_WINDOW,
        }
    }
}

impl RelayPolicy {
    /// Enable the relay path. Runtimes call this to opt the engine into
    /// active use. Inherits the secure defaults (contact gate on,
    /// rate/bandwidth caps populated).
    #[must_use]
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }

    /// Override the failure threshold + window.
    #[must_use]
    pub fn with_failure_trigger(mut self, threshold: u32, window: Duration) -> Self {
        self.fail_threshold = threshold.max(1);
        self.fail_window = window;
        self
    }

    /// Override the forward-path resource caps (#193). All windows share
    /// `window`; `0` for a rate field means "block all forwards". A zero
    /// window is clamped to [`MIN_RELAY_LIMIT_WINDOW`] so it can never disable
    /// accounting.
    #[must_use]
    pub fn with_forward_limits(
        mut self,
        max_per_sender: u32,
        max_total: u32,
        max_bytes: u64,
        window: Duration,
    ) -> Self {
        self.max_forwards_per_sender = max_per_sender;
        self.max_total_forwards = max_total;
        self.max_forward_bytes_per_window = max_bytes;
        self.limit_window = window.max(MIN_RELAY_LIMIT_WINDOW);
        self
    }
}

/// Per-peer direct-DM failure tracker. Holds the timestamps of recent
/// failures so the sliding-window `needs_relay` check is cheap.
#[derive(Debug, Default)]
struct PeerRelayState {
    /// Timestamps of recent direct-DM failures, oldest first.
    recent_failures: Vec<Instant>,
    /// Set once the peer crosses the threshold; cleared on the next
    /// direct success. Used to count `direct_recovered_after_relay`.
    in_relay_mode: bool,
}

/// Atomic relay telemetry counters.
#[derive(Debug, Default)]
pub struct RelayStats {
    relay_sent: AtomicU64,
    relay_received: AtomicU64,
    relay_forwarded: AtomicU64,
    relay_refused_bad_signature: AtomicU64,
    relay_refused_stale: AtomicU64,
    relay_refused_policy_disabled: AtomicU64,
    relay_dropped_revoked: AtomicU64,
    direct_recovered_after_relay: AtomicU64,
    // #193 forward-path hardening counters:
    relay_refused_not_a_contact: AtomicU64,
    relay_refused_blocked: AtomicU64,
    relay_refused_rate_limited: AtomicU64,
    relay_refused_bandwidth_exceeded: AtomicU64,
    /// Total bytes successfully transmitted on the relay-forward path (the
    /// observable bandwidth metric). Incremented only when a reservation is
    /// committed after transport success, using the encoded inner-envelope
    /// wire size.
    relay_forward_bytes: AtomicU64,
}

/// JSON-friendly snapshot of [`RelayStats`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct RelayStatsSnapshot {
    /// DMs this node sent wrapped in a `RelayedDm` via a relay peer.
    pub relay_sent: u64,
    /// Relayed DMs this node received as the final recipient.
    pub relay_received: u64,
    /// Relayed DMs this node forwarded as an intermediate relay.
    pub relay_forwarded: u64,
    /// Inbound relayed DMs refused — bad header signature.
    pub relay_refused_bad_signature: u64,
    /// Inbound relayed DMs refused — stale (likely replay).
    pub relay_refused_stale: u64,
    /// Inbound relayed DMs refused — relay path disabled by policy.
    pub relay_refused_policy_disabled: u64,
    /// Inbound relayed DMs dropped because the inner envelope's origin
    /// agent is in this node's revocation set. Enforces the revocation
    /// gate on the relay delivery/forward path, which does not otherwise
    /// traverse the `dm_inbox` gossip-path revocation check.
    pub relay_dropped_revoked: u64,
    /// Peers that returned to a healthy direct path after having been
    /// in relay mode — proves the fallback is transient, not sticky.
    pub direct_recovered_after_relay: u64,
    /// Inbound relayed DMs refused — sender is not a contact
    /// (`require_contact_to_relay`, #193).
    pub relay_refused_not_a_contact: u64,
    /// Inbound relayed DMs refused — sender is an explicitly blocked
    /// contact (#193). Refused unconditionally on the forward arm.
    pub relay_refused_blocked: u64,
    /// Inbound relayed DMs refused — per-sender/global forward rate
    /// exceeded (#193).
    pub relay_refused_rate_limited: u64,
    /// Inbound relayed DMs refused — per-window bandwidth cap exceeded
    /// (#193).
    pub relay_refused_bandwidth_exceeded: u64,
    /// Total bytes committed to forward on the relay path (#193) — the
    /// observable bandwidth metric for the cap above.
    pub relay_forward_bytes: u64,
}

impl RelayStats {
    /// Build a JSON-friendly snapshot. Cheap; relaxed reads.
    #[must_use]
    pub fn snapshot(&self) -> RelayStatsSnapshot {
        RelayStatsSnapshot {
            relay_sent: self.relay_sent.load(Ordering::Relaxed),
            relay_received: self.relay_received.load(Ordering::Relaxed),
            relay_forwarded: self.relay_forwarded.load(Ordering::Relaxed),
            relay_refused_bad_signature: self.relay_refused_bad_signature.load(Ordering::Relaxed),
            relay_refused_stale: self.relay_refused_stale.load(Ordering::Relaxed),
            relay_refused_policy_disabled: self
                .relay_refused_policy_disabled
                .load(Ordering::Relaxed),
            relay_dropped_revoked: self.relay_dropped_revoked.load(Ordering::Relaxed),
            direct_recovered_after_relay: self.direct_recovered_after_relay.load(Ordering::Relaxed),
            relay_refused_not_a_contact: self.relay_refused_not_a_contact.load(Ordering::Relaxed),
            relay_refused_blocked: self.relay_refused_blocked.load(Ordering::Relaxed),
            relay_refused_rate_limited: self.relay_refused_rate_limited.load(Ordering::Relaxed),
            relay_refused_bandwidth_exceeded: self
                .relay_refused_bandwidth_exceeded
                .load(Ordering::Relaxed),
            relay_forward_bytes: self.relay_forward_bytes.load(Ordering::Relaxed),
        }
    }
}

/// A pending or successfully committed relay-forward charge. Pending entries
/// participate in every cap so concurrent admissions cannot oversubscribe;
/// they are never window-pruned while the send is in flight. A successful
/// commit starts its accounting window at the transmission time.
#[derive(Debug)]
struct RelayCharge {
    reservation_id: Option<u64>,
    sender: [u8; 32],
    recorded_at: Instant,
    bytes: u64,
}

/// #193 forward-path resource state. Pending reservations and committed
/// forwards share one ledger behind one mutex, making admission atomic across
/// the per-sender, global, and bandwidth caps.
#[derive(Debug, Default)]
struct RelayLimiter {
    charges: Vec<RelayCharge>,
    next_reservation_id: u64,
}

impl RelayLimiter {
    /// Drop committed entries older than `window`. Pending reservations stay
    /// until their send commits or their guard is dropped.
    fn prune(&mut self, now: Instant, window: Duration) {
        self.charges.retain(|charge| {
            charge.reservation_id.is_some()
                || now.saturating_duration_since(charge.recorded_at) < window
        });
    }

    fn would_exceed_bytes(&self, additional_bytes: u64, limit: u64) -> bool {
        let total = self
            .charges
            .iter()
            .try_fold(additional_bytes, |total, charge| {
                total.checked_add(charge.bytes)
            });
        match total {
            Some(total) => total > limit,
            None => true,
        }
    }

    fn reserve(&mut self, sender: [u8; 32], now: Instant, bytes: u64) -> u64 {
        let reservation_id = self.next_reservation_id;
        self.next_reservation_id = self.next_reservation_id.wrapping_add(1);
        self.charges.push(RelayCharge {
            reservation_id: Some(reservation_id),
            sender,
            recorded_at: now,
            bytes,
        });
        reservation_id
    }

    fn commit(&mut self, reservation_id: u64, now: Instant) -> Option<u64> {
        let charge = self
            .charges
            .iter_mut()
            .find(|charge| charge.reservation_id == Some(reservation_id))?;
        charge.reservation_id = None;
        charge.recorded_at = now;
        Some(charge.bytes)
    }

    fn cancel(&mut self, reservation_id: u64) {
        self.charges
            .retain(|charge| charge.reservation_id != Some(reservation_id));
    }
}

/// In-flight quota reservation for one relay forward.
///
/// Dropping this guard without calling [`commit`](Self::commit) releases all
/// reserved sender/global/byte capacity. This makes destination, encoding,
/// send, cancellation, and early-return failures fail-open for legitimate
/// later traffic without any check-then-act race.
#[must_use = "dropping the reservation cancels the relay admission"]
pub struct RelayForwardReservation<'a> {
    relay: &'a PeerRelay,
    reservation_id: Option<u64>,
}

impl RelayForwardReservation<'_> {
    /// Commit quota and success telemetry after the transport confirms that
    /// the forward was transmitted. Consumes the guard, so a retry cannot
    /// double-commit the same reservation.
    pub fn commit(mut self) {
        let Some(reservation_id) = self.reservation_id.take() else {
            return;
        };
        let committed_bytes = self
            .relay
            .limiter_lock()
            .commit(reservation_id, Instant::now());
        if let Some(bytes) = committed_bytes {
            self.relay
                .stats
                .relay_forwarded
                .fetch_add(1, Ordering::Relaxed);
            self.relay
                .stats
                .relay_forward_bytes
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }
}

impl Drop for RelayForwardReservation<'_> {
    fn drop(&mut self) {
        if let Some(reservation_id) = self.reservation_id.take() {
            self.relay.limiter_lock().cancel(reservation_id);
        }
    }
}

/// Application-level peer-relay engine.
///
/// Tracks per-peer direct-DM failures, decides when a peer
/// [`needs_relay`](PeerRelay::needs_relay), selects a relay candidate,
/// builds + verifies [`RelayHeader`]s, and classifies inbound
/// [`RelayedDm`]s. The failure/state map is behind `per_peer`; the
/// #193 forward-path resource caps (per-sender + global forward rate and
/// bandwidth) are behind a separate `limiter` mutex so the two concerns
/// never contend on the same lock.
#[derive(Debug)]
pub struct PeerRelay {
    policy: RelayPolicy,
    stats: RelayStats,
    per_peer: Mutex<HashMap<[u8; 32], PeerRelayState>>,
    limiter: Mutex<RelayLimiter>,
}

impl Default for PeerRelay {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerRelay {
    /// Construct with the default (disabled) policy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            policy: RelayPolicy::default(),
            stats: RelayStats::default(),
            per_peer: Mutex::new(HashMap::new()),
            limiter: Mutex::new(RelayLimiter::default()),
        }
    }

    /// Construct with an explicit policy.
    #[must_use]
    pub fn with_policy(policy: RelayPolicy) -> Self {
        Self {
            policy,
            stats: RelayStats::default(),
            per_peer: Mutex::new(HashMap::new()),
            limiter: Mutex::new(RelayLimiter::default()),
        }
    }

    /// Borrow the active policy.
    #[must_use]
    pub fn policy(&self) -> &RelayPolicy {
        &self.policy
    }

    /// Borrow the telemetry counters.
    #[must_use]
    pub fn stats(&self) -> &RelayStats {
        &self.stats
    }

    /// Record that an inbound relayed DM was dropped because its inner
    /// envelope's origin agent is revoked. Called by the relay-DM
    /// listener's revocation gate before delivering or forwarding, so a
    /// revoked origin cannot use the relay path to bypass the revocation
    /// check that the direct-DM re-injection would otherwise skip.
    pub fn record_relay_dropped_revoked(&self) {
        self.stats
            .relay_dropped_revoked
            .fetch_add(1, Ordering::Relaxed);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], PeerRelayState>> {
        match self.per_peer.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn limiter_lock(&self) -> std::sync::MutexGuard<'_, RelayLimiter> {
        match self.limiter.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Record that a direct DM to `peer` failed. Prunes failures older
    /// than `fail_window` so the sliding-window count stays accurate.
    pub fn record_direct_failure(&self, peer: &AgentId) {
        let now = Instant::now();
        let window = self.policy.fail_window;
        let mut guard = self.lock();
        let entry = guard.entry(peer.0).or_default();
        entry
            .recent_failures
            .retain(|t| now.saturating_duration_since(*t) < window);
        entry.recent_failures.push(now);
    }

    /// Record that a direct DM to `peer` succeeded. Clears the failure
    /// history; if the peer had crossed into relay mode, increments
    /// `direct_recovered_after_relay` — proving the fallback was
    /// transient.
    pub fn record_direct_success(&self, peer: &AgentId) {
        let mut guard = self.lock();
        if let Some(entry) = guard.get_mut(&peer.0) {
            entry.recent_failures.clear();
            if entry.in_relay_mode {
                entry.in_relay_mode = false;
                drop(guard);
                self.stats
                    .direct_recovered_after_relay
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Whether `peer` currently needs a relay: the policy is enabled
    /// **and** the peer has at least `fail_threshold` direct-DM
    /// failures within `fail_window`. Marks the peer `in_relay_mode` so
    /// a later [`record_direct_success`](PeerRelay::record_direct_success)
    /// can count the recovery.
    #[must_use]
    pub fn needs_relay(&self, peer: &AgentId) -> bool {
        if !self.policy.enabled {
            return false;
        }
        let now = Instant::now();
        let window = self.policy.fail_window;
        let threshold = self.policy.fail_threshold as usize;
        let mut guard = self.lock();
        let Some(entry) = guard.get_mut(&peer.0) else {
            return false;
        };
        entry
            .recent_failures
            .retain(|t| now.saturating_duration_since(*t) < window);
        let needs = entry.recent_failures.len() >= threshold;
        if needs {
            entry.in_relay_mode = true;
        }
        needs
    }

    /// Pick a relay candidate for `dst` from `candidates`. The caller
    /// supplies a *pre-filtered* list (the runtime is responsible for
    /// passing only peers it has a healthy direct path to, with public
    /// addresses, ideally geographically distinct). This MVP picks the
    /// first candidate that is neither `dst` nor `sender` — health and
    /// geo-distinctness filtering is the caller's job and is documented
    /// for the X0X-0070b wiring.
    #[must_use]
    pub fn select_relay(
        &self,
        candidates: &[AgentId],
        dst: &AgentId,
        sender: &AgentId,
    ) -> Option<AgentId> {
        candidates
            .iter()
            .find(|c| c.0 != dst.0 && c.0 != sender.0)
            .copied()
    }

    /// Build a [`RelayedDm`] wrapping `inner` for delivery to `dst`,
    /// signed by the sender. `sender_public_key` is the sender's
    /// ML-DSA-65 public key bytes; `sign` is a closure that produces an
    /// ML-DSA-65 signature over the supplied bytes (typically
    /// `SigningContext::sign`). Increments `relay_sent`.
    ///
    /// # Errors
    ///
    /// Returns `Err` with the closure's error string if signing fails.
    pub fn build_relayed_dm<F>(
        &self,
        dst: &AgentId,
        sender: &AgentId,
        sender_public_key: Vec<u8>,
        originated_at_unix_ms: u64,
        inner: DmEnvelope,
        sign: F,
    ) -> Result<RelayedDm, String>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, String>,
    {
        let signing_bytes = RelayHeader::signing_bytes(
            RelayHeader::VERSION,
            &dst.0,
            &sender.0,
            &sender_public_key,
            originated_at_unix_ms,
        );
        let signature = sign(&signing_bytes)?;
        let header = RelayHeader {
            version: RelayHeader::VERSION,
            dst_agent_id: dst.0,
            sender_agent_id: sender.0,
            sender_public_key,
            originated_at_unix_ms,
            signature,
        };
        self.stats.relay_sent.fetch_add(1, Ordering::Relaxed);
        Ok(RelayedDm { header, inner })
    }

    /// Classify an inbound [`RelayedDm`] from the perspective of *this*
    /// node, whose agent id is `local_agent_id`, at wall-clock
    /// `now_unix_ms`. `is_sender_contact` is the caller's resolution of
    /// whether the header's authenticated `sender_agent_id` is an
    /// *explicitly-trusted* contact (Known/Trusted — NOT a merely-
    /// discovered `Unknown` entry); `is_sender_blocked` is whether it is
    /// an explicitly-blocked contact. The listener resolves both from
    /// `ContactStore` before calling. Classification refusal telemetry is
    /// updated here; forwarding quota and success telemetry are updated by
    /// [`reserve_forward`](Self::reserve_forward) and its reservation guard.
    ///
    /// Classification order (each refusal is fail-closed and counted):
    /// - Policy disabled → `Refuse(PolicyDisabled)`. Runs **before** the
    ///   (expensive ML-DSA-65) header verification so an unsolicited
    ///   relay frame to a disabled node cannot force a signature check.
    /// - Header fails verification → `Refuse(BadSignature)`.
    /// - `originated_at` older than `freshness`, or more than
    ///   [`RELAY_CLOCK_SKEW_TOLERANCE_MS`] ahead of `now_unix_ms` →
    ///   `Refuse(Stale)`.
    /// - `dst == local` → [`RelayDisposition::DeliverLocally`],
    ///   `relay_received` += 1. Receiving is not relaying, so the
    ///   contact gate and resource caps below do NOT apply here.
    /// - otherwise (forward arm, #193 hardening):
    ///   1. `is_sender_blocked` → `Refuse(Blocked)`,
    ///      `relay_refused_blocked` += 1. **Unconditional** — the
    ///      operator's blocklist wins even on an open relay
    ///      (`require_contact_to_relay = false`) and before rate caps.
    ///   2. `require_contact_to_relay && !is_sender_contact` →
    ///      `Refuse(NotAContact)`, `relay_refused_not_a_contact` += 1.
    ///      Only Known/Trusted pass; a discovery-only `Unknown` entry
    ///      does not.
    ///   3. all pass → return [`RelayDisposition::Forward`]. The caller must
    ///      resolve and encode the destination, then call
    ///      [`reserve_forward`](Self::reserve_forward) immediately before the
    ///      transport send.
    #[must_use]
    pub fn disposition_for(
        &self,
        relayed: &RelayedDm,
        local_agent_id: &AgentId,
        now_unix_ms: u64,
        is_sender_contact: bool,
        is_sender_blocked: bool,
    ) -> RelayDisposition {
        // DoS guard: reject on the disabled-policy path before doing any
        // ML-DSA-65 signature work, so a disabled relay cannot be made to
        // burn CPU verifying attacker-supplied headers.
        if !self.policy.enabled {
            self.stats
                .relay_refused_policy_disabled
                .fetch_add(1, Ordering::Relaxed);
            return RelayDisposition::Refuse(RelayRefusal::PolicyDisabled);
        }
        if !relayed.header.verify() {
            self.stats
                .relay_refused_bad_signature
                .fetch_add(1, Ordering::Relaxed);
            return RelayDisposition::Refuse(RelayRefusal::BadSignature);
        }
        let freshness_ms = self.policy.freshness.as_millis() as u64;
        let originated = relayed.header.originated_at_unix_ms;
        // Refuse far-future timestamps: without this bound `saturating_sub`
        // reports age 0 for any future `originated_at`, so a captured header
        // stays replayable until the local clock catches up.
        let from_future = originated > now_unix_ms.saturating_add(RELAY_CLOCK_SKEW_TOLERANCE_MS);
        let too_old = now_unix_ms.saturating_sub(originated) > freshness_ms;
        if from_future || too_old {
            self.stats
                .relay_refused_stale
                .fetch_add(1, Ordering::Relaxed);
            return RelayDisposition::Refuse(RelayRefusal::Stale);
        }
        // Final recipient: receiving a relayed DM addressed to us is not
        // relaying — the contact gate and resource caps target the forward
        // arm where this node spends its own uplink.
        if relayed.header.dst_agent_id == local_agent_id.0 {
            self.stats.relay_received.fetch_add(1, Ordering::Relaxed);
            return RelayDisposition::DeliverLocally;
        }
        // Forward arm — #193 hardening. Cheapest gates first (no lock).
        // A blocked contact is refused unconditionally — the operator's
        // blocklist wins even on an explicitly-open relay
        // (require_contact_to_relay = false) and before rate/bandwidth.
        if is_sender_blocked {
            self.stats
                .relay_refused_blocked
                .fetch_add(1, Ordering::Relaxed);
            return RelayDisposition::Refuse(RelayRefusal::Blocked);
        }
        // Contact gate: only explicitly-trusted contacts (Known/Trusted)
        // pass — a merely-discovered Unknown entry does NOT, so the gate
        // means "my contacts", not "anyone I've seen".
        if self.policy.require_contact_to_relay && !is_sender_contact {
            self.stats
                .relay_refused_not_a_contact
                .fetch_add(1, Ordering::Relaxed);
            return RelayDisposition::Refuse(RelayRefusal::NotAContact);
        }
        RelayDisposition::Forward {
            dst_agent_id: relayed.header.dst_agent_id,
        }
    }

    /// Atomically reserve per-sender, global, and byte capacity for an
    /// already-resolved and encoded forward.
    ///
    /// Pending reservations count against every cap, preventing concurrent
    /// callers from oversubscribing. The returned guard cancels on drop; call
    /// [`RelayForwardReservation::commit`] exactly once and only after the
    /// transport reports a successful transmission.
    ///
    /// # Errors
    ///
    /// Returns [`RelayRefusal::RateLimited`] when either forward-count cap is
    /// full, or [`RelayRefusal::BandwidthExceeded`] when admitting `bytes`
    /// would exceed the byte cap. The corresponding refusal counter is
    /// incremented once.
    pub fn reserve_forward(
        &self,
        sender_agent_id: [u8; 32],
        bytes: u64,
    ) -> Result<RelayForwardReservation<'_>, RelayRefusal> {
        let now = Instant::now();
        let window = self.policy.limit_window.max(MIN_RELAY_LIMIT_WINDOW);
        let mut limiter = self.limiter_lock();
        limiter.prune(now, window);

        let sender_count = limiter
            .charges
            .iter()
            .filter(|charge| charge.sender == sender_agent_id)
            .count();
        if sender_count >= self.policy.max_forwards_per_sender as usize
            || limiter.charges.len() >= self.policy.max_total_forwards as usize
        {
            self.stats
                .relay_refused_rate_limited
                .fetch_add(1, Ordering::Relaxed);
            return Err(RelayRefusal::RateLimited);
        }
        if limiter.would_exceed_bytes(bytes, self.policy.max_forward_bytes_per_window) {
            self.stats
                .relay_refused_bandwidth_exceeded
                .fetch_add(1, Ordering::Relaxed);
            return Err(RelayRefusal::BandwidthExceeded);
        }

        let reservation_id = limiter.reserve(sender_agent_id, now, bytes);
        Ok(RelayForwardReservation {
            relay: self,
            reservation_id: Some(reservation_id),
        })
    }

    /// Number of peers with tracked failure state (diagnostic).
    #[must_use]
    pub fn tracked_peer_count(&self) -> usize {
        self.lock().len()
    }

    /// Drop a peer's relay state — call on disconnect so the map
    /// doesn't grow unbounded.
    pub fn forget_peer(&self, peer: &AgentId) {
        self.lock().remove(&peer.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::{DmBody, DmPayload};
    use crate::identity::AgentKeypair;

    fn aid(seed: u8) -> AgentId {
        AgentId([seed; 32])
    }

    /// Minimal opaque inner envelope for the relay-wrapping tests. The
    /// relay never inspects `inner`, so a placeholder is sufficient.
    fn dummy_inner() -> DmEnvelope {
        DmEnvelope {
            protocol_version: 1,
            request_id: [7u8; 16],
            sender_agent_id: [1u8; 32],
            sender_machine_id: [2u8; 32],
            recipient_agent_id: [3u8; 32],
            created_at_unix_ms: 1_000,
            expires_at_unix_ms: 60_000,
            body: DmBody::Payload(DmPayload {
                kem_ciphertext: vec![0u8; 8],
                body_nonce: [0u8; 12],
                body_ciphertext: vec![0u8; 8],
            }),
            signature: vec![0u8; 8],
        }
    }

    #[test]
    fn relay_disabled_by_default() {
        // Why: the MVP relay path must not engage unless a runtime
        // explicitly opts in. A default-constructed engine never says a
        // peer needs a relay, even after a flood of failures.
        let relay = PeerRelay::new();
        assert!(!relay.policy().enabled);
        let peer = aid(9);
        for _ in 0..10 {
            relay.record_direct_failure(&peer);
        }
        assert!(
            !relay.needs_relay(&peer),
            "disabled policy must never trigger relay regardless of failures"
        );
    }

    #[test]
    fn needs_relay_after_threshold_failures_within_window() {
        // Why: the core trigger — N direct-DM failures inside the
        // sliding window marks the peer needs_relay. Below threshold,
        // it does not.
        let relay = PeerRelay::with_policy(RelayPolicy::enabled());
        let peer = aid(1);
        relay.record_direct_failure(&peer);
        relay.record_direct_failure(&peer);
        assert!(
            !relay.needs_relay(&peer),
            "2 failures < default threshold 3 — no relay yet"
        );
        relay.record_direct_failure(&peer);
        assert!(
            relay.needs_relay(&peer),
            "3 failures == threshold — peer now needs a relay"
        );
    }

    #[test]
    fn direct_success_clears_failures_and_counts_recovery() {
        // Why: relay mode must be transient. A peer that recovers a
        // direct path clears its failure history AND increments
        // `direct_recovered_after_relay` exactly once.
        let relay = PeerRelay::with_policy(RelayPolicy::enabled());
        let peer = aid(2);
        for _ in 0..3 {
            relay.record_direct_failure(&peer);
        }
        assert!(relay.needs_relay(&peer), "peer entered relay mode");

        relay.record_direct_success(&peer);
        assert!(
            !relay.needs_relay(&peer),
            "direct success clears the failure history"
        );
        assert_eq!(
            relay.stats().snapshot().direct_recovered_after_relay,
            1,
            "recovery from relay mode is counted once"
        );

        // A second success without re-entering relay mode does not
        // double-count.
        relay.record_direct_success(&peer);
        assert_eq!(
            relay.stats().snapshot().direct_recovered_after_relay,
            1,
            "recovery counter does not double-count"
        );
    }

    #[test]
    fn select_relay_skips_dst_and_sender() {
        // Why: a relay candidate must be a third party — never the
        // destination (pointless) nor the sender (can't relay to self).
        let relay = PeerRelay::new();
        let sender = aid(1);
        let dst = aid(2);
        let r1 = aid(3);
        let r2 = aid(4);

        // dst and sender are filtered out; first eligible wins.
        let candidates = vec![dst, sender, r1, r2];
        assert_eq!(relay.select_relay(&candidates, &dst, &sender), Some(r1));

        // No eligible candidate → None.
        let only_endpoints = vec![dst, sender];
        assert_eq!(
            relay.select_relay(&only_endpoints, &dst, &sender),
            None,
            "no third party available — cannot relay"
        );
    }

    #[test]
    fn relay_header_sign_verify_roundtrip() {
        // Why: the relay's whole trust model is the header signature.
        // A header built + signed by a real keypair must verify; the
        // embedded agent_id must derive from the embedded pubkey.
        let kp = AgentKeypair::generate().expect("keypair");
        let sender = kp.agent_id();
        let dst = aid(50);
        let (pub_bytes, sec_bytes) = kp.to_bytes();
        let originated = 1_700_000_000_000u64;

        let signing_bytes = RelayHeader::signing_bytes(
            RelayHeader::VERSION,
            &dst.0,
            &sender.0,
            &pub_bytes,
            originated,
        );
        let secret = ant_quic::MlDsaSecretKey::from_bytes(&sec_bytes).expect("secret");
        let signature =
            ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(&secret, &signing_bytes)
                .expect("sign");

        let header = RelayHeader {
            version: RelayHeader::VERSION,
            dst_agent_id: dst.0,
            sender_agent_id: sender.0,
            sender_public_key: pub_bytes,
            originated_at_unix_ms: originated,
            signature: signature.as_bytes().to_vec(),
        };
        assert!(header.verify(), "a correctly signed header must verify");
    }

    #[test]
    fn relay_header_verify_rejects_tampered_dst() {
        // Why: if a relay could be fed a header with a swapped dst, an
        // attacker could redirect relayed traffic. Tampering any signed
        // field must break verification.
        let kp = AgentKeypair::generate().expect("keypair");
        let sender = kp.agent_id();
        let dst = aid(50);
        let (pub_bytes, sec_bytes) = kp.to_bytes();
        let originated = 1_700_000_000_000u64;
        let signing_bytes = RelayHeader::signing_bytes(
            RelayHeader::VERSION,
            &dst.0,
            &sender.0,
            &pub_bytes,
            originated,
        );
        let secret = ant_quic::MlDsaSecretKey::from_bytes(&sec_bytes).expect("secret");
        let signature =
            ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(&secret, &signing_bytes)
                .expect("sign");

        let mut header = RelayHeader {
            version: RelayHeader::VERSION,
            dst_agent_id: dst.0,
            sender_agent_id: sender.0,
            sender_public_key: pub_bytes,
            originated_at_unix_ms: originated,
            signature: signature.as_bytes().to_vec(),
        };
        // Tamper the destination after signing.
        header.dst_agent_id = aid(99).0;
        assert!(
            !header.verify(),
            "a tampered dst must break the header signature"
        );
    }

    #[test]
    fn relay_header_verify_rejects_forged_origin() {
        // Why: a header where `sender_agent_id` does not derive from
        // `sender_public_key` must be rejected — otherwise a relay
        // could attribute the request to a forged origin even with a
        // self-consistent signature over the forged id.
        let kp = AgentKeypair::generate().expect("keypair");
        let (pub_bytes, sec_bytes) = kp.to_bytes();
        let dst = aid(50);
        let forged_sender = aid(123); // does NOT derive from pub_bytes
        let originated = 1_700_000_000_000u64;
        // Sign over the forged sender id — self-consistent signature,
        // but the id/pubkey binding is broken.
        let signing_bytes = RelayHeader::signing_bytes(
            RelayHeader::VERSION,
            &dst.0,
            &forged_sender.0,
            &pub_bytes,
            originated,
        );
        let secret = ant_quic::MlDsaSecretKey::from_bytes(&sec_bytes).expect("secret");
        let signature =
            ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(&secret, &signing_bytes)
                .expect("sign");
        let header = RelayHeader {
            version: RelayHeader::VERSION,
            dst_agent_id: dst.0,
            sender_agent_id: forged_sender.0,
            sender_public_key: pub_bytes,
            originated_at_unix_ms: originated,
            signature: signature.as_bytes().to_vec(),
        };
        assert!(
            !header.verify(),
            "sender_agent_id must derive from sender_public_key"
        );
    }

    #[test]
    fn build_relayed_dm_increments_relay_sent_and_produces_verifiable_header() {
        // Why: the sender-side build path must produce a header that a
        // relay will accept, and must count the send.
        let kp = AgentKeypair::generate().expect("keypair");
        let sender = kp.agent_id();
        let dst = aid(60);
        let (pub_bytes, sec_bytes) = kp.to_bytes();
        let secret = ant_quic::MlDsaSecretKey::from_bytes(&sec_bytes).expect("secret");

        let relay = PeerRelay::with_policy(RelayPolicy::enabled());
        let relayed = relay
            .build_relayed_dm(
                &dst,
                &sender,
                pub_bytes,
                1_700_000_000_000,
                dummy_inner(),
                |bytes| {
                    ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(&secret, bytes)
                        .map(|s| s.as_bytes().to_vec())
                        .map_err(|e| format!("{e:?}"))
                },
            )
            .expect("build_relayed_dm");

        assert!(
            relayed.header.verify(),
            "build_relayed_dm must produce a verifiable header"
        );
        assert_eq!(relay.stats().snapshot().relay_sent, 1);
    }

    #[test]
    fn disposition_delivers_locally_when_we_are_the_dst() {
        // Why: a relayed DM addressed to us must be classified for
        // local delivery and counted as `relay_received`.
        let kp = AgentKeypair::generate().expect("keypair");
        let sender = kp.agent_id();
        let (pub_bytes, sec_bytes) = kp.to_bytes();
        let secret = ant_quic::MlDsaSecretKey::from_bytes(&sec_bytes).expect("secret");
        let local = aid(70);

        let relay = PeerRelay::with_policy(RelayPolicy::enabled());
        let now_ms = 1_700_000_000_000u64;
        let relayed = relay
            .build_relayed_dm(&local, &sender, pub_bytes, now_ms, dummy_inner(), |bytes| {
                ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(&secret, bytes)
                    .map(|s| s.as_bytes().to_vec())
                    .map_err(|e| format!("{e:?}"))
            })
            .expect("build");

        assert_eq!(
            relay.disposition_for(&relayed, &local, now_ms + 100, false, false),
            RelayDisposition::DeliverLocally
        );
        assert_eq!(relay.stats().snapshot().relay_received, 1);
    }

    #[test]
    fn disposition_forwards_when_we_are_an_intermediate_relay() {
        // Why: a relayed DM addressed to someone else must be classified
        // for one-hop forward to its dst. Classification lives in
        // `disposition_for` and no longer charges quotas; admission + byte
        // accounting is exercised via `reserve_forward` (see the dedicated
        // reservation tests).
        let kp = AgentKeypair::generate().expect("keypair");
        let sender = kp.agent_id();
        let (pub_bytes, sec_bytes) = kp.to_bytes();
        let secret = ant_quic::MlDsaSecretKey::from_bytes(&sec_bytes).expect("secret");
        let dst = aid(80);
        let we_are_the_relay = aid(81);

        let relay = PeerRelay::with_policy(RelayPolicy::enabled());
        let now_ms = 1_700_000_000_000u64;
        let relayed = relay
            .build_relayed_dm(&dst, &sender, pub_bytes, now_ms, dummy_inner(), |bytes| {
                ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(&secret, bytes)
                    .map(|s| s.as_bytes().to_vec())
                    .map_err(|e| format!("{e:?}"))
            })
            .expect("build");

        assert_eq!(
            relay.disposition_for(&relayed, &we_are_the_relay, now_ms + 100, true, false),
            RelayDisposition::Forward {
                dst_agent_id: dst.0
            }
        );
        // Classification only: no quota charge, no telemetry bump.
        assert_eq!(
            relay.stats().snapshot().relay_forwarded,
            0,
            "disposition_for classifies only; admission happens in reserve_forward"
        );
    }

    #[test]
    fn disposition_refuses_stale_relayed_dm() {
        // Why: a relayed envelope older than the freshness budget is a
        // likely replay of a captured envelope — refuse it.
        let kp = AgentKeypair::generate().expect("keypair");
        let sender = kp.agent_id();
        let (pub_bytes, sec_bytes) = kp.to_bytes();
        let secret = ant_quic::MlDsaSecretKey::from_bytes(&sec_bytes).expect("secret");
        let local = aid(90);

        let relay = PeerRelay::with_policy(RelayPolicy::enabled());
        let originated_ms = 1_700_000_000_000u64;
        let relayed = relay
            .build_relayed_dm(
                &local,
                &sender,
                pub_bytes,
                originated_ms,
                dummy_inner(),
                |bytes| {
                    ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(&secret, bytes)
                        .map(|s| s.as_bytes().to_vec())
                        .map_err(|e| format!("{e:?}"))
                },
            )
            .expect("build");

        // "now" is 31 s past origination — beyond the 30 s freshness.
        let now_ms = originated_ms + 31_000;
        assert_eq!(
            relay.disposition_for(&relayed, &local, now_ms, false, false),
            RelayDisposition::Refuse(RelayRefusal::Stale)
        );
        assert_eq!(relay.stats().snapshot().relay_refused_stale, 1);
    }

    #[test]
    fn disposition_refuses_far_future_relayed_dm() {
        // Why: a header timestamped far in the future would otherwise read
        // as age 0 under `saturating_sub` and stay replayable until the
        // local clock caught up. It must be refused as stale, mirroring
        // the DM path's clock-skew bound.
        let kp = AgentKeypair::generate().expect("keypair");
        let sender = kp.agent_id();
        let (pub_bytes, sec_bytes) = kp.to_bytes();
        let secret = ant_quic::MlDsaSecretKey::from_bytes(&sec_bytes).expect("secret");
        let local = aid(91);

        let relay = PeerRelay::with_policy(RelayPolicy::enabled());
        let now_ms = 1_700_000_000_000u64;
        // Origination is 31 s *ahead* of now — past the 30 s skew bound.
        let originated_ms = now_ms + RELAY_CLOCK_SKEW_TOLERANCE_MS + 1_000;
        let relayed = relay
            .build_relayed_dm(
                &local,
                &sender,
                pub_bytes,
                originated_ms,
                dummy_inner(),
                |bytes| {
                    ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(&secret, bytes)
                        .map(|s| s.as_bytes().to_vec())
                        .map_err(|e| format!("{e:?}"))
                },
            )
            .expect("build");

        assert_eq!(
            relay.disposition_for(&relayed, &local, now_ms, false, false),
            RelayDisposition::Refuse(RelayRefusal::Stale)
        );
        assert_eq!(relay.stats().snapshot().relay_refused_stale, 1);

        // A header just inside the skew bound is still accepted.
        let fresh = relay
            .build_relayed_dm(
                &local,
                &sender,
                kp.to_bytes().0,
                now_ms + 1_000,
                dummy_inner(),
                |bytes| {
                    ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(&secret, bytes)
                        .map(|s| s.as_bytes().to_vec())
                        .map_err(|e| format!("{e:?}"))
                },
            )
            .expect("build");
        assert_eq!(
            relay.disposition_for(&fresh, &local, now_ms, false, false),
            RelayDisposition::DeliverLocally
        );
    }

    #[test]
    fn disposition_refuses_when_policy_disabled() {
        // Why: with the relay path disabled, even a well-formed,
        // fresh, locally-addressed relayed DM is refused — the MVP
        // does not handle relay traffic until a runtime opts in.
        let kp = AgentKeypair::generate().expect("keypair");
        let sender = kp.agent_id();
        let (pub_bytes, sec_bytes) = kp.to_bytes();
        let secret = ant_quic::MlDsaSecretKey::from_bytes(&sec_bytes).expect("secret");
        let local = aid(95);

        // Build with an enabled engine (so the header is valid) but
        // classify with a disabled engine.
        let builder = PeerRelay::with_policy(RelayPolicy::enabled());
        let now_ms = 1_700_000_000_000u64;
        let relayed = builder
            .build_relayed_dm(&local, &sender, pub_bytes, now_ms, dummy_inner(), |bytes| {
                ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(&secret, bytes)
                    .map(|s| s.as_bytes().to_vec())
                    .map_err(|e| format!("{e:?}"))
            })
            .expect("build");

        let disabled = PeerRelay::new();
        assert_eq!(
            disabled.disposition_for(&relayed, &local, now_ms + 100, false, false),
            RelayDisposition::Refuse(RelayRefusal::PolicyDisabled)
        );
        assert_eq!(disabled.stats().snapshot().relay_refused_policy_disabled, 1);
    }

    #[test]
    fn forget_peer_drops_relay_state() {
        let relay = PeerRelay::with_policy(RelayPolicy::enabled());
        let peer = aid(1);
        relay.record_direct_failure(&peer);
        assert_eq!(relay.tracked_peer_count(), 1);
        relay.forget_peer(&peer);
        assert_eq!(relay.tracked_peer_count(), 0);
    }
    /// Build a fresh, verifiable `RelayedDm` addressed to `dst` (a forward
    /// request from the receiver's perspective), signed by a freshly
    /// generated sender keypair. The throwaway builder only exists so the
    /// header is valid; each test classifies with its own engine.
    fn signed_forward_envelope(dst: AgentId, now_ms: u64) -> RelayedDm {
        let kp = AgentKeypair::generate().expect("keypair");
        let sender = kp.agent_id();
        let (pub_bytes, sec_bytes) = kp.to_bytes();
        let secret = ant_quic::MlDsaSecretKey::from_bytes(&sec_bytes).expect("secret");
        let builder = PeerRelay::with_policy(RelayPolicy::enabled());
        builder
            .build_relayed_dm(&dst, &sender, pub_bytes, now_ms, dummy_inner(), |bytes| {
                ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(&secret, bytes)
                    .map(|s| s.as_bytes().to_vec())
                    .map_err(|e| format!("{e:?}"))
            })
            .expect("build")
    }

    #[test]
    fn disposition_refuses_non_contact_when_require_contact_set() {
        // Why (#193): with require_contact_to_relay = true (the secure
        // default), a forward request from a sender NOT in the contact
        // store must be refused — a stranger can no longer spend the
        // relay's uplink by self-keying a valid header.
        let dst = aid(40);
        let we = aid(41);
        let now_ms = 1_700_000_000_000u64;
        let relayed = signed_forward_envelope(dst, now_ms);

        let relay = PeerRelay::with_policy(RelayPolicy::enabled()); // require_contact defaults true
        assert_eq!(
            relay.disposition_for(&relayed, &we, now_ms + 100, false, false),
            RelayDisposition::Refuse(RelayRefusal::NotAContact)
        );
        assert_eq!(relay.stats().snapshot().relay_refused_not_a_contact, 1);
        assert_eq!(relay.stats().snapshot().relay_forwarded, 0);
    }

    #[test]
    fn disposition_forwards_for_contact_when_require_contact_set() {
        // Why (#193): the contact gate is a gate, not a block — a known
        // contact's forward request classifies as Forward. Classification
        // (`disposition_for`) no longer charges quotas; the caller admits
        // and commits via `reserve_forward`, and the committed bytes are
        // observable. This pins the classification-vs-admission split.
        let dst = aid(42);
        let we = aid(43);
        let now_ms = 1_700_000_000_000u64;
        let relayed = signed_forward_envelope(dst, now_ms);

        let relay = PeerRelay::with_policy(RelayPolicy::enabled());
        // Classification only — no quota charge, no telemetry bump.
        assert_eq!(
            relay.disposition_for(&relayed, &we, now_ms + 100, true, false),
            RelayDisposition::Forward {
                dst_agent_id: dst.0
            }
        );
        assert_eq!(
            relay.stats().snapshot().relay_forwarded,
            0,
            "disposition_for classifies only; admission happens in reserve_forward"
        );

        // Admission: reserve the predicted wire size and commit once the
        // transport confirms transmission.
        const FORWARD_BYTES: u64 = 512;
        relay
            .reserve_forward(relayed.header.sender_agent_id, FORWARD_BYTES)
            .expect("contact-gated forward admits")
            .commit();
        let snap = relay.stats().snapshot();
        assert_eq!(snap.relay_forwarded, 1);
        assert_eq!(
            snap.relay_forward_bytes, FORWARD_BYTES,
            "commit charges the exact reserved byte count, once"
        );
    }

    #[test]
    fn open_relay_forwards_for_stranger_when_contact_gate_off() {
        // Why (#193): an operator who explicitly opts into an open relay
        // (require_contact_to_relay = false) still forwards for
        // strangers — the gate is opt-out, and rate/bandwidth caps still
        // apply underneath.
        let dst = aid(44);
        let we = aid(45);
        let now_ms = 1_700_000_000_000u64;
        let relayed = signed_forward_envelope(dst, now_ms);

        let mut policy = RelayPolicy::enabled();
        policy.require_contact_to_relay = false;
        let relay = PeerRelay::with_policy(policy);
        assert_eq!(
            relay.disposition_for(&relayed, &we, now_ms + 100, false, false),
            RelayDisposition::Forward {
                dst_agent_id: dst.0
            }
        );
    }

    #[test]
    fn deliver_locally_not_gated_by_contact_check() {
        // Why (#193): receiving a relayed DM addressed to us is not
        // relaying. A non-contact sender can still reach us via relay —
        // the contact gate targets only the forward arm.
        let kp = AgentKeypair::generate().expect("keypair");
        let sender = kp.agent_id();
        let (pub_bytes, sec_bytes) = kp.to_bytes();
        let secret = ant_quic::MlDsaSecretKey::from_bytes(&sec_bytes).expect("secret");
        let local = aid(46);
        let relay = PeerRelay::with_policy(RelayPolicy::enabled());
        let now_ms = 1_700_000_000_000u64;
        let relayed = relay
            .build_relayed_dm(&local, &sender, pub_bytes, now_ms, dummy_inner(), |b| {
                ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(&secret, b)
                    .map(|s| s.as_bytes().to_vec())
                    .map_err(|e| format!("{e:?}"))
            })
            .expect("build");
        assert_eq!(
            relay.disposition_for(&relayed, &local, now_ms + 100, false, false),
            RelayDisposition::DeliverLocally
        );
    }

    #[test]
    fn reserve_forward_refuses_when_sender_rate_limit_exceeded() {
        // Why (#193): rate admission lives in `reserve_forward`, not
        // `disposition_for` (which classifies only). A sender holding more
        // than max_forwards_per_sender pending/committed forwards within
        // the window is throttled: the (cap+1)-th reservation from the SAME
        // sender is refused with RateLimited. Global + bandwidth caps are
        // loosened so only the per-sender gate fires. Held reservations
        // count against the cap (concurrent admissions cannot oversubscribe),
        // and committing each charges it exactly once.
        let sender = aid(7).0;
        let policy = RelayPolicy::enabled().with_forward_limits(
            2,         // max_per_sender
            1_000_000, // max_total (loose)
            u64::MAX,  // max_bytes (loose)
            Duration::from_secs(60),
        );
        let relay = PeerRelay::with_policy(policy);

        // First two reservations from this sender admit and are held.
        let r1 = relay.reserve_forward(sender, 100).expect("first admits");
        let r2 = relay.reserve_forward(sender, 100).expect("second admits");
        // Third reservation from the SAME sender is refused while the first
        // two are still outstanding (pending charges count toward the cap).
        assert_eq!(
            relay.reserve_forward(sender, 100).err(),
            Some(RelayRefusal::RateLimited)
        );
        let snap = relay.stats().snapshot();
        assert_eq!(snap.relay_refused_rate_limited, 1);
        assert_eq!(snap.relay_forwarded, 0, "nothing committed yet");

        // Committing the two held forwards charges each exactly once.
        r1.commit();
        r2.commit();
        let snap = relay.stats().snapshot();
        assert_eq!(snap.relay_forwarded, 2);
        assert_eq!(snap.relay_forward_bytes, 200);
    }

    #[test]
    fn reserve_forward_refuses_when_global_rate_limit_exceeded() {
        // Why (#193): the global concurrent-forward cap bounds total
        // forwards across ALL senders. Admission lives in `reserve_forward`:
        // with max_total_forwards = 1, a second reservation from a DIFFERENT
        // sender is refused while the first is still outstanding.
        let policy = RelayPolicy::enabled().with_forward_limits(
            1_000_000, // max_per_sender (loose)
            1,         // max_total
            u64::MAX,  // max_bytes (loose)
            Duration::from_secs(60),
        );
        let relay = PeerRelay::with_policy(policy);

        // First forward (sender A) admits and is held.
        let held = relay
            .reserve_forward(aid(1).0, 100)
            .expect("first global forward admits");
        // A different sender is still refused — the global budget is full.
        assert_eq!(
            relay.reserve_forward(aid(2).0, 100).err(),
            Some(RelayRefusal::RateLimited)
        );
        assert_eq!(relay.stats().snapshot().relay_refused_rate_limited, 1);
        drop(held);
    }

    #[test]
    fn reserve_forward_refuses_when_bandwidth_cap_exceeded() {
        // Why (#193): once cumulative reserved bytes in the window would
        // exceed max_forward_bytes_per_window, further admissions are
        // refused with BandwidthExceeded. Admission lives in
        // `reserve_forward`; the refusal + zero committed bytes are
        // observable. With a 1-byte cap, reserving any non-zero size
        // overflows it immediately → fail-closed refusal.
        let policy = RelayPolicy::enabled().with_forward_limits(
            1_000_000, // max_per_sender (loose)
            1_000_000, // max_total (loose)
            1,         // max_bytes
            Duration::from_secs(60),
        );
        let relay = PeerRelay::with_policy(policy);

        assert_eq!(
            relay.reserve_forward(aid(1).0, 100).err(),
            Some(RelayRefusal::BandwidthExceeded)
        );
        let snap = relay.stats().snapshot();
        assert_eq!(snap.relay_refused_bandwidth_exceeded, 1);
        assert_eq!(snap.relay_forwarded, 0);
        assert_eq!(
            snap.relay_forward_bytes, 0,
            "a refused admission commits no bytes"
        );
    }
    #[test]
    fn disposition_refuses_blocked_sender_unconditionally() {
        // Why (#193 followup): a blocked contact is refused on the forward
        // arm EVEN on an explicitly-open relay (require_contact_to_relay =
        // false). The operator's blocklist always wins — it is not a rate
        // limit that a blocked peer can spend budget against.
        let dst = aid(70);
        let we = aid(71);
        let now_ms = 1_700_000_000_000u64;
        let relayed = signed_forward_envelope(dst, now_ms);

        let mut policy = RelayPolicy::enabled();
        policy.require_contact_to_relay = false; // open relay
        let relay = PeerRelay::with_policy(policy);

        // Blocked + not-a-contact → still Blocked (gate is unconditional +
        // checked before the contact gate).
        assert_eq!(
            relay.disposition_for(&relayed, &we, now_ms + 100, false, true),
            RelayDisposition::Refuse(RelayRefusal::Blocked)
        );
        // Even if the sender were (impossibly) both "a contact" and blocked,
        // the Blocked gate runs first.
        assert_eq!(
            relay.disposition_for(&relayed, &we, now_ms + 100, true, true),
            RelayDisposition::Refuse(RelayRefusal::Blocked)
        );
        let snap = relay.stats().snapshot();
        assert_eq!(snap.relay_refused_blocked, 2);
        assert_eq!(snap.relay_forwarded, 0);
    }

    #[test]
    fn disposition_refuses_blocked_before_rate_limit() {
        // Why (#193 followup): the Blocked gate runs before the rate caps,
        // so a blocked sender bursting past max_forwards_per_sender is
        // refused with Blocked, not RateLimited.
        let dst = aid(72);
        let we = aid(73);
        let now_ms = 1_700_000_000_000u64;
        let relayed = signed_forward_envelope(dst, now_ms);

        // Open relay (require_contact=false) with a tight per-sender cap:
        // without the Blocked gate the first forward would succeed (it is
        // under the cap). is_sender_blocked=true must short-circuit to
        // Blocked, proving the gate runs before the rate caps.
        let mut policy = RelayPolicy::enabled().with_forward_limits(
            1,
            1_000_000,
            u64::MAX,
            Duration::from_secs(60),
        );
        policy.require_contact_to_relay = false;
        let relay = PeerRelay::with_policy(policy);
        assert_eq!(
            relay.disposition_for(&relayed, &we, now_ms + 100, false, true),
            RelayDisposition::Refuse(RelayRefusal::Blocked)
        );
        let snap = relay.stats().snapshot();
        assert_eq!(snap.relay_refused_blocked, 1);
        assert_eq!(snap.relay_forwarded, 0, "a blocked sender never forwards");
        assert_eq!(
            snap.relay_refused_rate_limited, 0,
            "Blocked must be reported, not RateLimited"
        );
    }

    #[test]
    fn unknown_contact_does_not_pass_contact_gate() {
        // Why (#193 followup): the contact gate means "my contacts", not
        // "anyone I've discovered". An auto-discovered `Unknown` entry (from
        // register_announced_machine → add_machine) must NOT pass — the
        // listener resolves Unknown to is_sender_contact=false, which the
        // engine then refuses as NotAContact when require_contact_to_relay
        // is set. This test pins the engine half of that contract.
        let dst = aid(74);
        let we = aid(75);
        let now_ms = 1_700_000_000_000u64;
        let relayed = signed_forward_envelope(dst, now_ms);

        let relay = PeerRelay::with_policy(RelayPolicy::enabled()); // require_contact default true
                                                                    // is_sender_contact=false models an Unknown (or absent) sender.
        assert_eq!(
            relay.disposition_for(&relayed, &we, now_ms + 100, false, false),
            RelayDisposition::Refuse(RelayRefusal::NotAContact)
        );
        // A Known/Trusted contact (is_sender_contact=true) does pass.
        assert_eq!(
            relay.disposition_for(&relayed, &we, now_ms + 100, true, false),
            RelayDisposition::Forward {
                dst_agent_id: dst.0
            }
        );
    }

    #[test]
    fn dropped_reservations_free_capacity_and_never_charge_counters() {
        // Why: a reservation models an in-flight forward. If the
        // destination is unavailable or the forward fails before
        // transmission, the caller drops the guard (cancel) — it must NOT
        // commit any counter, and the freed capacity must be reusable by
        // later legitimate traffic. Repeated reserve-then-drop churn must
        // leave sender, global, and byte capacity pristine.
        let sender = aid(5).0;
        let policy = RelayPolicy::enabled().with_forward_limits(
            2,   // max_per_sender
            2,   // max_total
            256, // max_bytes
            Duration::from_secs(60),
        );
        let relay = PeerRelay::with_policy(policy);

        // Churn several reservations that each "fail" and are dropped.
        for _ in 0..5 {
            let reservation = relay
                .reserve_forward(sender, 100)
                .expect("dropped reservation admits while capacity is free");
            drop(reservation); // models destination-unavailable / early failure
        }

        // Counters untouched: nothing committed.
        let snap = relay.stats().snapshot();
        assert_eq!(snap.relay_forwarded, 0);
        assert_eq!(snap.relay_forward_bytes, 0);
        assert_eq!(snap.relay_refused_rate_limited, 0);
        assert_eq!(snap.relay_refused_bandwidth_exceeded, 0);

        // Capacity is fully reusable: a fresh reservation still admits.
        let reusable = relay
            .reserve_forward(sender, 100)
            .expect("capacity is reusable after dropped reservations");
        drop(reusable);
    }

    #[test]
    fn failed_forward_then_retry_commits_exactly_once() {
        // Why: the retry/error path must not double-commit or leak
        // capacity. A forward that reserves then fails (send error /
        // encode failure) drops its guard — cancelling its admission
        // without charging. The legitimate retry reserves fresh and
        // commits once: exactly one charge lands, and the failed attempt's
        // capacity was freed so the retry could even reuse the same
        // sender slot.
        let sender = aid(9).0;
        let policy = RelayPolicy::enabled().with_forward_limits(
            1, // max_per_sender: the retry only fits if the
            // failed attempt freed its slot
            1_000_000,
            u64::MAX,
            Duration::from_secs(60),
        );
        let relay = PeerRelay::with_policy(policy);

        // First attempt reserves, then the transport reports a send failure.
        let failed = relay
            .reserve_forward(sender, 64)
            .expect("first attempt reserves");
        drop(failed); // send failure → cancel, no charge

        // The slot is free again (cap=1), so the retry admits and commits.
        relay
            .reserve_forward(sender, 64)
            .expect("retry reserves after the failed attempt freed capacity")
            .commit();

        let snap = relay.stats().snapshot();
        assert_eq!(snap.relay_forwarded, 1, "only the retry committed");
        assert_eq!(snap.relay_forward_bytes, 64);
    }

    #[test]
    fn dropping_one_reservation_frees_just_that_slot() {
        // Why: cancelling (dropping) a single in-flight reservation must
        // release exactly its sender/global/byte capacity — no more, no
        // less. One freed slot admits exactly one new reservation while
        // other outstanding reservations stay counted.
        let sender = aid(3).0;
        let policy = RelayPolicy::enabled().with_forward_limits(
            2, // max_per_sender
            1_000_000,
            u64::MAX,
            Duration::from_secs(60),
        );
        let relay = PeerRelay::with_policy(policy);

        let r1 = relay.reserve_forward(sender, 10).expect("first slot");
        let _r2 = relay.reserve_forward(sender, 10).expect("second slot");
        // Both per-sender slots are full.
        assert_eq!(
            relay.reserve_forward(sender, 10).err(),
            Some(RelayRefusal::RateLimited)
        );

        // Cancel just r1 → exactly one slot frees.
        drop(r1);
        let _r3 = relay
            .reserve_forward(sender, 10)
            .expect("freed slot re-admits");
        // Full again — the cancellation freed one slot, not two.
        assert_eq!(
            relay.reserve_forward(sender, 10).err(),
            Some(RelayRefusal::RateLimited)
        );
    }

    #[test]
    fn commit_charges_counters_once_and_consumes_capacity() {
        // Why: commit() consumes the guard (so a retry cannot double-commit
        // the same reservation) and the guard's Drop is a no-op once
        // committed — the reservation_id is taken. The observable contract:
        // a committed charge bumps relay_forwarded by exactly one and
        // relay_forward_bytes by exactly the reserved bytes, AND it keeps
        // consuming a cap slot (a post-commit Drop cannot spuriously free
        // it). Had commit's implicit drop cancelled the charge, the global
        // cap below would have re-opened.
        let policy = RelayPolicy::enabled().with_forward_limits(
            1_000_000, // per-sender loose
            2,         // global cap
            u64::MAX,
            Duration::from_secs(60),
        );
        let relay = PeerRelay::with_policy(policy);

        relay.reserve_forward(aid(1).0, 111).unwrap().commit();
        relay.reserve_forward(aid(2).0, 222).unwrap().commit();

        // Both committed charges occupy the global cap → a third (distinct
        // sender) is refused. This proves commit's Drop was a no-op.
        assert_eq!(
            relay.reserve_forward(aid(3).0, 100).err(),
            Some(RelayRefusal::RateLimited),
            "committed charges still consume the global cap"
        );

        let snap = relay.stats().snapshot();
        assert_eq!(snap.relay_forwarded, 2);
        assert_eq!(snap.relay_forward_bytes, 333);
    }

    #[test]
    fn concurrent_admissions_never_oversubscribe_global_cap() {
        // Why: pending and committed charges share one ledger behind one
        // mutex, so concurrent callers cannot race past the global cap.
        // Many threads, each reserving for a distinct sender against a
        // small global budget, must admit exactly `cap` — never more.
        use std::sync::atomic::AtomicUsize;
        use std::sync::{Arc, Barrier};
        use std::thread;

        const CAP: usize = 4;
        const THREADS: usize = 16;
        let relay = Arc::new(PeerRelay::with_policy(
            RelayPolicy::enabled().with_forward_limits(
                1_000_000, // per-sender loose (distinct senders anyway)
                CAP as u32,
                u64::MAX,
                Duration::from_secs(60),
            ),
        ));
        // Release every thread onto reserve_forward at once, then hold them
        // (holding their reservations) until main has counted, so no slot
        // frees prematurely and the cap is the real binding constraint.
        let start = Arc::new(Barrier::new(THREADS));
        let hold = Arc::new(Barrier::new(THREADS + 1));
        let admitted = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for i in 0..THREADS {
            let relay = Arc::clone(&relay);
            let start = Arc::clone(&start);
            let hold = Arc::clone(&hold);
            let admitted = Arc::clone(&admitted);
            let refused = Arc::clone(&refused);
            handles.push(thread::spawn(move || {
                let sender = [i as u8; 32];
                start.wait();
                match relay.reserve_forward(sender, 64) {
                    Ok(r) => {
                        admitted.fetch_add(1, Ordering::SeqCst);
                        hold.wait(); // keep the slot reserved until counted
                        drop(r);
                    }
                    Err(RelayRefusal::RateLimited) => {
                        refused.fetch_add(1, Ordering::SeqCst);
                        hold.wait();
                    }
                    Err(other) => panic!("unexpected refusal {other:?}"),
                }
            }));
        }

        // All threads have now reserved or been refused and are holding at
        // `hold`; main joins the barrier so the counts are stable to read.
        hold.wait();
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            admitted.load(Ordering::SeqCst),
            CAP,
            "exactly the global cap admits, never more"
        );
        assert_eq!(
            refused.load(Ordering::SeqCst),
            THREADS - CAP,
            "the rest are refused with RateLimited"
        );
        assert_eq!(
            relay.stats().snapshot().relay_forwarded,
            0,
            "none committed"
        );
    }

    #[test]
    fn relay_policy_with_forward_limits_clamps_zero_window() {
        // Why: `with_forward_limits` is the direct programmatic builder for
        // the rate/bandwidth caps. A zero window would silently disable
        // accounting (committed charges would prune on the next admission),
        // so it must clamp to MIN_RELAY_LIMIT_WINDOW. The positive 1 ms
        // floor survives unchanged.
        let zero = RelayPolicy::enabled().with_forward_limits(10, 100, 1_024, Duration::ZERO);
        assert_eq!(
            zero.limit_window, MIN_RELAY_LIMIT_WINDOW,
            "Duration::ZERO must clamp to the 1 ms floor"
        );

        let one_ms =
            RelayPolicy::enabled().with_forward_limits(10, 100, 1_024, Duration::from_millis(1));
        assert_eq!(
            one_ms.limit_window, MIN_RELAY_LIMIT_WINDOW,
            "1 ms is the floor and survives unchanged"
        );

        // A generous window is never clamped down.
        let generous =
            RelayPolicy::enabled().with_forward_limits(10, 100, 1_024, Duration::from_secs(60));
        assert_eq!(generous.limit_window, Duration::from_secs(60));
    }
}
