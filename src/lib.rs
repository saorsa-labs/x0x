#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(missing_docs)]

//! # x0x
//!
//! Agent-to-agent gossip network for AI systems.
//!
//! Named after a tic-tac-toe sequence — X, zero, X — inspired by the
//! *WarGames* insight that adversarial games between equally matched
//! opponents always end in a draw. The only winning move is not to play.
//!
//! x0x applies this principle to AI-human relations: there is no winner
//! in an adversarial framing, so the rational strategy is cooperation.
//!
//! Built on [saorsa-gossip](https://github.com/saorsa-labs/saorsa-gossip)
//! and [ant-quic](https://github.com/saorsa-labs/ant-quic) by
//! [Saorsa Labs](https://saorsalabs.com). *Saorsa* is Scottish Gaelic
//! for **freedom**.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use x0x::{network::NetworkConfig, Agent};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create an online agent with the default network configuration.
//! // Omitting with_network_config builds an offline identity-only agent.
//! let agent = Agent::builder()
//!     .with_network_config(NetworkConfig::default())
//!     .build()
//!     .await?;
//!
//! // Join the x0x network
//! agent.join_network().await?;
//!
//! // Subscribe to a topic and receive messages
//! let mut rx = agent.subscribe("coordination").await?;
//! while let Some(msg) = rx.recv().await {
//!     println!("topic: {:?}, payload: {:?}", msg.topic, msg.payload);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Bootstrap Nodes
//!
//! Agents configured with [`network::NetworkConfig`]`::default()` connect to
//! Saorsa Labs' global bootstrap network:
//! - NYC, US · SFO, US · Helsinki, FI
//! - Nuremberg, DE · Singapore, SG · Sydney, JP
//!
//! These nodes provide initial peer discovery and NAT traversal.

/// Error types for x0x identity and network operations.
pub mod error;

/// Core identity types for x0x agents.
///
/// This module provides the cryptographic identity foundation for x0x:
/// - [`crate::identity::MachineId`]: Machine-pinned identity for QUIC authentication
/// - [`crate::identity::AgentId`]: Portable agent identity for cross-machine persistence
pub mod identity;

/// Key storage serialization for x0x identities.
///
/// This module provides serialization and deserialization functions for
/// persistent storage of MachineKeypair and AgentKeypair.
pub mod storage;

/// Signed identity revocation records and the grow-only revocation set.
///
/// See [`revocation::RevocationRecord`] for the authority rules (self- and
/// issuer-revocation only) and [`revocation::RevocationSet`] for the local,
/// gossip-fed set consulted at every trust gate.
pub mod revocation;

/// Bootstrap node discovery and connection.
///
/// This module handles initial connection to bootstrap nodes with
/// exponential backoff retry logic and peer cache integration.
pub mod bootstrap;
/// Network transport layer for x0x.
pub mod network;

/// Per-peer bidirectional byte-streams over ant-quic (tailnet Phase 1, #132).
pub mod streams;

/// Local port-forwarder over tailnet byte-streams (tailnet Phase 1, #132 T4).
pub mod forward;

/// Contact store with trust levels for message filtering.
pub mod contacts;

/// Trust evaluation for `(identity, machine)` pairs.
///
/// The [`trust::TrustEvaluator`] combines an agent's trust level with its
/// identity type and machine records to produce a [`trust::TrustDecision`].
pub mod trust;

/// Agent-to-agent connectivity helpers.
///
/// Provides `ReachabilityInfo` (built from a `DiscoveredAgent`) and
/// `ConnectOutcome` for the result of `connect_to_agent()`.
pub mod connectivity;

/// Gossip overlay networking for x0x.
pub mod gossip;

/// CRDT-based collaborative task lists.
pub mod crdt;

/// CRDT-backed key-value store.
pub mod kv;

/// High-level group management (MLS + KvStore + gossip).
pub mod groups;

/// MLS (Messaging Layer Security) group encryption.
pub mod mls;

/// A2A (Agent2Agent) interoperability — Agent Card adapter (ADR-0017).
pub mod a2a;

/// Direct agent-to-agent messaging.
///
/// Point-to-point communication that bypasses gossip for private,
/// efficient, reliable delivery between connected agents.
pub mod direct;

/// Direct messaging over gossip — the v1 C path per
/// `docs/design/dm-over-gossip.md`. Provides signed+encrypted envelopes,
/// recipient-specific inbox topics, dedupe, and application-layer ACKs.
pub mod dm;

/// Mesh-wide DM capability advertisement + cache. Senders consult this
/// store to decide whether to use the gossip DM path or fall back to
/// raw-QUIC for a given recipient.
pub mod dm_capability;

/// Background service that publishes this agent's capability advert and
/// consumes peers' adverts into a shared [`dm_capability::CapabilityStore`].
pub mod dm_capability_service;

/// Background service that subscribes to this agent's DM inbox topic,
/// verifies + decrypts incoming envelopes, and bridges them into
/// [`direct::DirectMessaging`].
pub mod dm_inbox;

/// Sender-side gossip DM path — envelope construction, publish + retry,
/// and `InFlightAcks` wait.
pub mod dm_send;

/// Application-level peer relay (X0X-0070) — Tailscale-style fallback that
/// wraps an opaque, end-to-end-encrypted [`dm::DmEnvelope`] in a cleartext,
/// signed [`peer_relay::RelayHeader`] so a third peer can forward a DM when
/// the direct path is unreachable.
pub mod peer_relay;

/// Presence system — beacons, FOAF discovery, and online/offline events.
pub mod presence;

/// Self-update system with ML-DSA-65 signature verification and staged rollout.
pub mod upgrade;

/// File transfer protocol types and state management.
pub mod files;

pub mod connect;
/// Secure Tier-1 remote exec protocol and runtime.
pub mod exec;

/// The x0x Constitution — The Four Laws of Intelligent Coexistence — embedded at compile time.
pub mod constitution;

/// Privacy-preserving log identifier wrappers (salted-hash redaction).
pub mod logging;

/// Shared API endpoint registry consumed by both x0xd and the x0x CLI.
pub mod api;

/// CLI infrastructure and command implementations.
pub mod cli;

/// HTTP/WebSocket server: axum router, handlers, and the daemon serving entrypoint.
pub mod server;

// Re-export key gossip types (including new pubsub components)
pub use gossip::{
    GossipConfig, GossipRuntime, PubSubManager, PubSubMessage, PubSubStats, PubSubStatsSnapshot,
    SigningContext, Subscription,
};

// Re-export direct messaging types
pub use direct::{DirectMessage, DirectMessageReceiver, DirectMessaging};

// Import Membership trait for HyParView join() method
use saorsa_gossip_membership::Membership as _;

/// The core agent that participates in the x0x gossip network.
///
/// Each agent is a peer — there is no client/server distinction.
/// Agents discover each other through gossip and communicate
/// via epidemic broadcast.
///
/// An Agent wraps an [`identity::Identity`] that provides:
/// - `machine_id`: Tied to this computer (for QUIC transport authentication)
/// - `agent_id`: Portable across machines (for agent persistence)
///
/// # Example
///
/// ```ignore
/// use x0x::Agent;
///
/// let agent = Agent::builder()
///     .build()
///     .await?;
///
/// println!("Agent ID: {}", agent.agent_id());
/// ```
pub struct Agent {
    identity: std::sync::Arc<identity::Identity>,
    /// The network node for P2P communication.
    #[allow(dead_code)]
    network: Option<std::sync::Arc<network::NetworkNode>>,
    /// The gossip runtime for pub/sub messaging.
    gossip_runtime: Option<std::sync::Arc<gossip::GossipRuntime>>,
    /// Bootstrap peer cache for quality-based peer selection across restarts.
    bootstrap_cache: Option<std::sync::Arc<ant_quic::BootstrapCache>>,
    /// Gossip cache adapter wrapping bootstrap_cache with coordinator advert storage.
    gossip_cache_adapter: Option<saorsa_gossip_coordinator::GossipCacheAdapter>,
    /// Cache of discovered agents from identity announcements.
    identity_discovery_cache: std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<identity::AgentId, DiscoveredAgent>>,
    >,
    /// Cache of discovered machine endpoints from machine announcements and
    /// agent→machine identity links.
    machine_discovery_cache: std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<identity::MachineId, DiscoveredMachine>>,
    >,
    /// Cache of discovered users from user announcements (self-asserted
    /// agent-ownership rosters).
    user_discovery_cache: std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<identity::UserId, DiscoveredUser>>,
    >,
    /// Ensures identity discovery listener is spawned once.
    identity_listener_started: std::sync::atomic::AtomicBool,
    /// How often to re-announce identity (seconds).
    heartbeat_interval_secs: u64,
    /// How long before a cache entry is filtered out (seconds).
    identity_ttl_secs: u64,
    /// Handle for the running heartbeat task, if started.
    heartbeat_handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Handle for the background discovery cache reaper task (periodic
    /// TTL pruning of identity/machine/user discovery caches). Added as
    /// the primary x0x-owned mitigation for the historical unbounded
    /// memory growth observed on long-running nodes.
    discovery_cache_reaper_handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Whether a rendezvous `ProviderSummary` advertisement is active.
    rendezvous_advertised: std::sync::atomic::AtomicBool,
    /// Contact store for trust evaluation of incoming identity announcements.
    contact_store: std::sync::Arc<tokio::sync::RwLock<contacts::ContactStore>>,
    /// Direct messaging infrastructure for point-to-point communication.
    direct_messaging: std::sync::Arc<direct::DirectMessaging>,
    /// Ensures network event reconciliation listener is spawned once.
    network_event_listener_started: std::sync::atomic::AtomicBool,
    /// Ensures direct message listener is spawned once.
    direct_listener_started: std::sync::atomic::AtomicBool,
    /// Presence system wrapper for beacons, FOAF discovery, and events.
    presence: Option<std::sync::Arc<presence::PresenceWrapper>>,
    /// Whether the user has consented to disclosing their identity in
    /// announcements.  Set by `announce_identity(true, true)` and respected
    /// by the heartbeat so it doesn't erase a consented disclosure.
    user_identity_consented: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Capability store populated by the advert service and consulted by
    /// `send_direct` to choose between gossip and raw-QUIC paths.
    capability_store: std::sync::Arc<dm_capability::CapabilityStore>,
    /// Watch channel that carries this agent's *outgoing* DM capabilities.
    /// `join_network` spawns the advert service with a placeholder (empty
    /// KEM pubkey). `start_dm_inbox` upgrades via this sender to trigger
    /// immediate republish.
    dm_capabilities_tx: std::sync::Arc<tokio::sync::watch::Sender<dm::DmCapabilities>>,
    /// In-flight DM ACK waiters shared between `send_direct` and the inbox.
    dm_inflight_acks: std::sync::Arc<dm::InFlightAcks>,
    /// Receiver-side dedupe cache.
    recent_delivery_cache: std::sync::Arc<dm::RecentDeliveryCache>,
    /// Handle for the running capability advert service.
    capability_advert_service:
        tokio::sync::Mutex<Option<dm_capability_service::CapabilityAdvertService>>,
    /// Handle for the running DM inbox service.
    dm_inbox_service: tokio::sync::Mutex<Option<dm_inbox::DmInboxService>>,
    /// In-memory grow-only revocation set.  Gate checks hold only a read lock
    /// and never await while holding it — write lock is taken only when
    /// applying a new revocation (rare) and when persisting to disk.
    revocation_set: std::sync::Arc<tokio::sync::RwLock<revocation::RevocationSet>>,
    /// Identity-scoped directory.  When `Some`, revocations.bin is saved here
    /// instead of `~/.x0x/`.
    identity_dir: Option<std::path::PathBuf>,
    /// Cancellation token driving deterministic teardown of all long-lived
    /// Agent background loops (identity/network-event/direct listeners and the
    /// presence broadcast-peer refresh). Cancelling it makes every token-aware
    /// loop break promptly; `shutdown()` cancels it before tearing down gossip
    /// and the network so listeners (which call network methods) stop first.
    shutdown_token: tokio_util::sync::CancellationToken,
    /// Registry of tracked background-task handles. Once `closed` is set (by
    /// `shutdown()`), `spawn_tracked` refuses to spawn — this defeats the
    /// join_network race where a listener could otherwise start after shutdown
    /// began. A plain `std::sync::Mutex` (not tokio) keeps lock holds trivially
    /// short: never await while holding it.
    tracked_tasks: std::sync::Arc<std::sync::Mutex<TrackedTasks>>,
    /// X0X-0070b: application-level peer-relay engine. Records direct-DM
    /// successes and failures so [`peer_relay::PeerRelay::needs_relay`] can
    /// drive the fallback decision. The engine is disabled by default
    /// (matches [`peer_relay::RelayPolicy::default`]) - it only acts once a
    /// runtime opts in via `[peer_relay] enabled = true` in the daemon's
    /// `NetworkConfig` TOML.
    peer_relay: std::sync::Arc<peer_relay::PeerRelay>,
    /// X0X-0070b: pre-filtered set of relay candidates the engine picks from
    /// when the direct path fails. Seeded from `NetworkConfig.peer_relay.candidates`
    /// at build time; future revisions merge in gossip-announced candidates
    /// at runtime, hence the `RwLock` for mutable runtime state.
    relay_candidates: std::sync::Arc<tokio::sync::RwLock<Vec<identity::AgentId>>>,
    /// Tailnet byte-stream accept loop state (#132 T1): a bounded channel
    /// surfacing inbound [`streams::PeerStream`]s that have cleared the
    /// identity gate, plus an idempotent started-flag for the accept loop.
    stream_accept: std::sync::Arc<streams::StreamAccept>,
}

/// Closed-flag task registry for deterministic Agent teardown.
///
/// `spawn_tracked` pushes handles here while `closed` is false; `shutdown()`
/// sets `closed` and drains the handles. The flag closes the join_network
/// shutdown race: a spawn requested after `shutdown()` began is dropped rather
/// than leaked.
struct TrackedTasks {
    closed: bool,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("identity", &self.identity)
            .field("network", &self.network.is_some())
            .field("gossip_runtime", &self.gossip_runtime.is_some())
            .field("bootstrap_cache", &self.bootstrap_cache.is_some())
            .field("gossip_cache_adapter", &self.gossip_cache_adapter.is_some())
            .finish()
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        if let Ok(mut handle_guard) = self.heartbeat_handle.try_lock() {
            if let Some(handle) = handle_guard.take() {
                handle.abort();
            }
        }
        if let Ok(mut reaper_guard) = self.discovery_cache_reaper_handle.try_lock() {
            if let Some(handle) = reaper_guard.take() {
                handle.abort();
            }
        }
    }
}

/// A message received from the gossip network.
#[derive(Debug, Clone)]
pub struct Message {
    /// The originating agent's identifier.
    pub origin: String,
    /// The message payload.
    pub payload: Vec<u8>,
    /// The topic this message was published to.
    pub topic: String,
}

/// Reserved gossip topic for signed identity announcements.
///
/// **v2** carries additional `reachable_via` / `relay_candidates` fields for
/// NAT-aware coordinator hints. v1 is retired; v0.18.x is yanked.
pub const IDENTITY_ANNOUNCE_TOPIC: &str = "x0x.identity.announce.v2";

/// Reserved gossip topic for signed machine endpoint announcements.
///
/// **v2** carries the same NAT-aware coordinator hints as the identity
/// topic. v1 is retired.
pub const MACHINE_ANNOUNCE_TOPIC: &str = "x0x.machine.announce.v2";

/// Reserved gossip topic for signed user announcements.
///
/// A `UserAnnouncement` is a user-signed list of `AgentCertificate`s —
/// it is the user saying "these are my agents", independent of whether
/// any individual agent has consented to disclose its user binding.
/// First introduced in v2 wire format.
pub const USER_ANNOUNCE_TOPIC: &str = "x0x.user.announce.v2";

/// Reserved gossip topic for signed identity revocation records.
///
/// Payload is a `bincode`-encoded `Vec<revocation::RevocationRecord>`.
/// Records are re-verified on receipt before insertion into the local
/// [`revocation::RevocationSet`].  The full local set is re-broadcast on each identity
/// heartbeat for partition-tolerant eventual convergence.
pub const REVOCATION_TOPIC: &str = "x0x.revocation.v1";

/// Return the shard-specific gossip topic for the given `agent_id`.
///
/// Each agent publishes identity announcements to a deterministic shard topic
/// (`x0x.identity.shard.v2.<u16>`) derived from its agent ID, in addition to
/// the broadcast topic. This distributes announcements across 65,536 shards so
/// that at scale not every node is forced to receive every announcement.
///
/// The shard is computed with `saorsa_gossip_rendezvous::calculate_shard`, which
/// applies BLAKE3(`"saorsa-rendezvous" || agent_id`) and takes the low 16 bits.
#[must_use]
pub fn shard_topic_for_agent(agent_id: &identity::AgentId) -> String {
    let shard = saorsa_gossip_rendezvous::calculate_shard(&agent_id.0);
    format!("x0x.identity.shard.v2.{shard}")
}

/// Return the shard-specific gossip topic for the given `machine_id`.
///
/// Machine shards let callers actively wait for a transport endpoint by
/// machine identity, then resolve agent/user identities onto that endpoint.
#[must_use]
pub fn shard_topic_for_machine(machine_id: &identity::MachineId) -> String {
    let shard = saorsa_gossip_rendezvous::calculate_shard(&machine_id.0);
    format!("x0x.machine.shard.v2.{shard}")
}

/// Return the shard-specific gossip topic for the given `user_id`.
///
/// Users publish their agent-ownership roster to a deterministic shard so
/// seekers can look up "which agents does UserId(X) claim?" without a full
/// broadcast subscription.
#[must_use]
pub fn shard_topic_for_user(user_id: &identity::UserId) -> String {
    let shard = saorsa_gossip_rendezvous::calculate_shard(&user_id.0);
    format!("x0x.user.shard.v2.{shard}")
}

/// Gossip topic prefix for rendezvous `ProviderSummary` advertisements.
pub const RENDEZVOUS_SHARD_TOPIC_PREFIX: &str = "x0x.rendezvous.shard";

/// Return the rendezvous shard gossip topic for the given `agent_id`.
///
/// Agents publish [`saorsa_gossip_rendezvous::ProviderSummary`] records to this
/// topic so that seekers can find them even when the two peers have never been
/// on the same gossip overlay partition.
#[must_use]
pub fn rendezvous_shard_topic_for_agent(agent_id: &identity::AgentId) -> String {
    let shard = saorsa_gossip_rendezvous::calculate_shard(&agent_id.0);
    format!("{RENDEZVOUS_SHARD_TOPIC_PREFIX}.{shard}")
}

/// Returns `true` if the IP address is globally routable (reachable from the
/// public internet).  Used to filter announcement addresses so that private,
/// link-local, loopback, and other non-routable addresses never propagate
/// through gossip — they would create dead-end cache entries on remote nodes.
///
/// `IpAddr::is_global()` is nightly-only, so we implement the check manually.
fn is_globally_routable(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_private()           // 10/8, 172.16/12, 192.168/16
                && !v4.is_loopback()   // 127/8
                && !v4.is_link_local() // 169.254/16
                && !v4.is_unspecified() // 0.0.0.0
                && !v4.is_broadcast()  // 255.255.255.255
                && !v4.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
                // Shared address space (100.64/10, RFC 6598 — CGNAT)
                && !(v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
        }
        std::net::IpAddr::V6(v6) => {
            let segs = v6.segments();
            !v6.is_loopback()                         // ::1
                && !v6.is_unspecified()               // ::
                && (segs[0] & 0xffc0) != 0xfe80       // link-local fe80::/10
                && (segs[0] & 0xfe00) != 0xfc00       // unique-local fc00::/7 (incl. fd00::/8)
                && (segs[0] & 0xfff0) != 0xfec0 // deprecated site-local fec0::/10
        }
    }
}

/// Whether an address is safe to publish on a globally-propagating channel
/// (identity heartbeat, agent card, presence beacon, gossip cache advert).
///
/// LAN-scoped discovery is handled by ant-quic's first-party mDNS on link-local
/// multicast, so we deliberately never share RFC1918, ULA, link-local, CGNAT,
/// or loopback addresses over global gossip. Remote peers cannot reach them,
/// and dialing them burns per-attempt connect budget on the receiver side.
///
/// This is stricter than `ant_quic::reachability::ReachabilityScope::Global`
/// because it also excludes CGNAT (100.64/10), documentation ranges, and
/// port-zero entries.
pub fn is_publicly_advertisable(addr: std::net::SocketAddr) -> bool {
    addr.port() > 0 && is_globally_routable(addr.ip())
}

fn filter_publicly_advertisable_addrs<I>(addresses: I) -> Vec<std::net::SocketAddr>
where
    I: IntoIterator<Item = std::net::SocketAddr>,
{
    addresses
        .into_iter()
        .filter(|addr| is_publicly_advertisable(*addr))
        .collect()
}

fn is_local_discovery_addr(addr: std::net::SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            !v4.is_unspecified()
                && !v4.is_broadcast()
                && !v4.is_documentation()
                && !v4.is_link_local()
        }
        std::net::IpAddr::V6(v6) => {
            let segs = v6.segments();
            !v6.is_unspecified() && (segs[0] & 0xffc0) != 0xfe80 && (segs[0] & 0xfff0) != 0xfec0
        }
    }
}

fn filter_local_discovery_addrs<I>(addresses: I) -> Vec<std::net::SocketAddr>
where
    I: IntoIterator<Item = std::net::SocketAddr>,
{
    let mut filtered = Vec::new();
    for addr in addresses {
        if is_local_discovery_addr(addr) && !filtered.contains(&addr) {
            filtered.push(addr);
        }
    }
    filtered
}

fn filter_discovery_announcement_addrs<I>(
    addresses: I,
    allow_local_scope: bool,
) -> Vec<std::net::SocketAddr>
where
    I: IntoIterator<Item = std::net::SocketAddr>,
{
    if allow_local_scope {
        filter_local_discovery_addrs(addresses)
    } else {
        filter_publicly_advertisable_addrs(addresses)
    }
}

/// Register a foreign agent's announced machine in the contact store.
///
/// Returns `true` if a new machine record was added, `false` otherwise
/// (the machine was already known, or the announcement is for the daemon's
/// own agent). The daemon deliberately never creates a contact entry for
/// itself: a self record would be noise on the `/contacts` surface and would
/// make contact-set assertions racy (issue #145). The two sibling actions in
/// the announce loop — epidemic re-broadcast and auto-connect — already
/// self-skip on `announced != own`; this helper makes the contact upsert the
/// third self-skipping site.
async fn register_announced_machine(
    contact_store: &std::sync::Arc<tokio::sync::RwLock<contacts::ContactStore>>,
    own_agent_id: identity::AgentId,
    announced_agent_id: identity::AgentId,
    announced_machine_id: identity::MachineId,
) -> bool {
    if announced_agent_id == own_agent_id {
        return false;
    }
    let mut store = contact_store.write().await;
    let record = contacts::MachineRecord::new(announced_machine_id, None);
    store.add_machine(&announced_agent_id, record)
}

fn local_scoped_bootstrap_addr(addr: std::net::SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || is_cgnat_v4(v4) || v4.is_link_local()
        }
        std::net::IpAddr::V6(v6) => {
            let segs = v6.segments();
            v6.is_loopback() || (segs[0] & 0xfe00) == 0xfc00 || (segs[0] & 0xffc0) == 0xfe80
        }
    }
}

fn allow_local_discovery_addresses(config: &network::NetworkConfig) -> bool {
    config.bootstrap_nodes.is_empty()
        || config
            .bootstrap_nodes
            .iter()
            .copied()
            .all(local_scoped_bootstrap_addr)
}

pub fn collect_local_interface_addrs(port: u16) -> Vec<std::net::SocketAddr> {
    fn is_cgnat(v4: std::net::Ipv4Addr) -> bool {
        v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64
    }

    fn addr_priority(ip: std::net::IpAddr) -> u8 {
        match ip {
            std::net::IpAddr::V4(v4) => {
                if is_globally_routable(std::net::IpAddr::V4(v4)) {
                    0
                } else if is_cgnat(v4) {
                    1
                } else {
                    2
                }
            }
            std::net::IpAddr::V6(v6) => {
                if is_globally_routable(std::net::IpAddr::V6(v6)) {
                    3
                } else {
                    4
                }
            }
        }
    }

    let mut ranked = Vec::new();

    let interfaces = match if_addrs::get_if_addrs() {
        Ok(interfaces) => interfaces,
        Err(_) => return Vec::new(),
    };

    for iface in interfaces {
        let ip = iface.ip();
        if ip.is_unspecified() || ip.is_loopback() {
            continue;
        }

        let addr = match ip {
            std::net::IpAddr::V4(v4) => {
                if v4.is_link_local() {
                    continue;
                }
                std::net::SocketAddr::new(std::net::IpAddr::V4(v4), port)
            }
            std::net::IpAddr::V6(v6) => {
                let segs = v6.segments();
                let is_link_local = (segs[0] & 0xffc0) == 0xfe80;
                if is_link_local {
                    continue;
                }
                std::net::SocketAddr::new(std::net::IpAddr::V6(v6), port)
            }
        };

        if !ranked.iter().any(|(_, existing)| *existing == addr) {
            ranked.push((addr_priority(addr.ip()), addr));
        }
    }

    ranked.sort_by_key(|(priority, addr)| (*priority, addr.is_ipv6()));
    ranked.into_iter().map(|(_, addr)| addr).collect()
}

fn is_cgnat_v4(v4: std::net::Ipv4Addr) -> bool {
    v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64
}

fn same_v4_24(a: std::net::Ipv4Addr, b: std::net::Ipv4Addr) -> bool {
    let a = a.octets();
    let b = b.octets();
    a[0] == b[0] && a[1] == b[1] && a[2] == b[2]
}

fn local_direct_probe_priority(
    addr: std::net::SocketAddr,
    local_v4s: &[std::net::Ipv4Addr],
) -> Option<u8> {
    let std::net::IpAddr::V4(v4) = addr.ip() else {
        return None;
    };
    if addr.port() == 0 || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() {
        return None;
    }
    if local_v4s.iter().any(|local| same_v4_24(*local, v4)) {
        return Some(0);
    }
    if v4.is_private() {
        return Some(1);
    }
    if is_cgnat_v4(v4) {
        return Some(2);
    }
    None
}

fn local_direct_probe_addrs_with_local_v4s(
    addresses: &[std::net::SocketAddr],
    local_v4s: &[std::net::Ipv4Addr],
) -> Vec<std::net::SocketAddr> {
    let mut ranked = addresses
        .iter()
        .copied()
        .filter_map(|addr| local_direct_probe_priority(addr, local_v4s).map(|rank| (rank, addr)))
        .collect::<Vec<_>>();
    ranked.sort_by_key(|(rank, addr)| (*rank, *addr));
    ranked.dedup_by_key(|(_, addr)| *addr);
    ranked.into_iter().map(|(_, addr)| addr).collect()
}

fn local_direct_probe_addrs(addresses: &[std::net::SocketAddr]) -> Vec<std::net::SocketAddr> {
    let local_v4s = collect_local_interface_addrs(0)
        .into_iter()
        .filter_map(|addr| match addr.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(_) => None,
        })
        .collect::<Vec<_>>();
    local_direct_probe_addrs_with_local_v4s(addresses, &local_v4s)
}

/// Default interval between identity heartbeat re-announcements (seconds).
///
/// Heartbeats are anti-entropy, not a hot-path delivery mechanism. Keep the
/// default at five minutes so bootstrap meshes do not spend their PubSub budget
/// on repeated signed identity/machine announcements. Each fresh announcement
/// still receives a one-shot receiver-side re-broadcast in
/// `start_identity_listener` for epidemic convergence.
pub const IDENTITY_HEARTBEAT_INTERVAL_SECS: u64 = 300;

/// Default TTL for discovered agent cache entries (seconds).
///
/// Entries not refreshed within this window are filtered from
/// [`Agent::presence`] and [`Agent::discovered_agents`].
pub const IDENTITY_TTL_SECS: u64 = 900;

const DISCOVERY_REBROADCAST_STATE_CAP: usize = 1024;
const DISCOVERY_REBROADCAST_STATE_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Interval (seconds) between runs of the background discovery cache reaper.
/// The reaper performs TTL-based pruning using the same identity_ttl
/// horizon as the query paths on the identity / machine / user discovery
/// HashMaps. This converts the caches from unbounded growth (only filtered
/// at read time) into bounded working-set + retention-window structures.
const DISCOVERY_CACHE_REAPER_INTERVAL_SECS: u64 = 120;

fn discovery_record_is_live(_announced_at: u64, last_seen: u64, cutoff: u64) -> bool {
    last_seen >= cutoff
}

fn should_rebroadcast_discovery_once<K>(
    state: &mut std::collections::HashMap<K, std::time::Instant>,
    key: K,
    now: std::time::Instant,
) -> bool
where
    K: Eq + std::hash::Hash,
{
    match state.entry(key) {
        std::collections::hash_map::Entry::Occupied(_) => false,
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(now);
            if state.len() > DISCOVERY_REBROADCAST_STATE_CAP {
                if let Some(cutoff) = now.checked_sub(DISCOVERY_REBROADCAST_STATE_TTL) {
                    state.retain(|_, seen_at| *seen_at >= cutoff);
                }
            }
            true
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IdentityAnnouncementUnsigned {
    agent_id: identity::AgentId,
    machine_id: identity::MachineId,
    user_id: Option<identity::UserId>,
    agent_certificate: Option<identity::AgentCertificate>,
    machine_public_key: Vec<u8>,
    addresses: Vec<std::net::SocketAddr>,
    announced_at: u64,
    /// NAT type string (e.g. "FullCone", "Symmetric", "Unknown").
    nat_type: Option<String>,
    /// Whether the machine can receive direct inbound connections.
    can_receive_direct: Option<bool>,
    /// Whether the machine advertises relay service capability to peers.
    ///
    /// This is a stable capability hint, not proof that the machine is
    /// actively relaying traffic right now.
    is_relay: Option<bool>,
    /// Whether the machine advertises coordinator capability to peers.
    ///
    /// This is a stable capability hint, not proof that the machine is
    /// actively coordinating a traversal right now.
    is_coordinator: Option<bool>,
    /// Coordinator machines through which this agent is reachable.
    ///
    /// When `can_receive_direct == Some(false)` (typically symmetric NAT),
    /// the advertising agent lists machine IDs of peers that can act as
    /// coordinators for hole-punching. Empty when the agent is directly
    /// reachable or has not yet learned any coordinator candidates.
    reachable_via: Vec<identity::MachineId>,
    /// Relay machines the advertising agent proposes as fallback paths.
    ///
    /// Used when hole-punching is not viable (extreme NAT). Empty by default.
    relay_candidates: Vec<identity::MachineId>,
}

/// Signed identity announcement broadcast by agents.
///
/// The outer pub/sub envelope is agent-signed (v2 message format), and this
/// payload is machine-signed to bind the daemon's PQC key to the announcement.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IdentityAnnouncement {
    /// Portable agent identity.
    pub agent_id: identity::AgentId,
    /// Machine identity for the daemon process.
    pub machine_id: identity::MachineId,
    /// Optional human identity (only when explicitly consented).
    pub user_id: Option<identity::UserId>,
    /// Optional user->agent certificate.
    pub agent_certificate: Option<identity::AgentCertificate>,
    /// Machine ML-DSA-65 public key bytes.
    pub machine_public_key: Vec<u8>,
    /// Machine ML-DSA-65 signature over the unsigned announcement.
    pub machine_signature: Vec<u8>,
    /// Reachability hints.
    pub addresses: Vec<std::net::SocketAddr>,
    /// Unix timestamp (seconds) of announcement creation.
    pub announced_at: u64,
    /// NAT type as detected by the network layer (e.g. "FullCone", "Symmetric").
    /// `None` when the network is not yet started or NAT type is undetermined.
    pub nat_type: Option<String>,
    /// Whether the machine can receive direct inbound connections.
    /// `None` when the network is not yet started.
    pub can_receive_direct: Option<bool>,
    /// Whether the machine advertises relay service capability to peers.
    ///
    /// This is a stable capability hint derived from transport configuration,
    /// not proof that the machine is actively relaying traffic right now.
    /// `None` when the network is not yet started.
    pub is_relay: Option<bool>,
    /// Whether the machine advertises coordinator capability to peers.
    ///
    /// This is a stable capability hint derived from transport configuration,
    /// not proof that the machine is actively coordinating a traversal right
    /// now. `None` when the network is not yet started.
    pub is_coordinator: Option<bool>,
    /// Coordinator machines through which this agent is reachable.
    ///
    /// Populated when the agent is behind NAT that blocks direct inbound
    /// connections (`can_receive_direct == Some(false)`). Callers should
    /// dial one of these coordinators first, then hole-punch via peer-ID
    /// traversal. Empty when the agent is directly reachable or has no
    /// coordinator candidates yet.
    pub reachable_via: Vec<identity::MachineId>,
    /// Relay machines the advertising agent proposes as fallback paths.
    ///
    /// Used when hole-punching is not viable (e.g. endpoint-dependent
    /// mapping). Empty by default.
    pub relay_candidates: Vec<identity::MachineId>,
}

impl IdentityAnnouncement {
    fn to_unsigned(&self) -> IdentityAnnouncementUnsigned {
        IdentityAnnouncementUnsigned {
            agent_id: self.agent_id,
            machine_id: self.machine_id,
            user_id: self.user_id,
            agent_certificate: self.agent_certificate.clone(),
            machine_public_key: self.machine_public_key.clone(),
            addresses: self.addresses.clone(),
            announced_at: self.announced_at,
            nat_type: self.nat_type.clone(),
            can_receive_direct: self.can_receive_direct,
            is_relay: self.is_relay,
            is_coordinator: self.is_coordinator,
            reachable_via: self.reachable_via.clone(),
            relay_candidates: self.relay_candidates.clone(),
        }
    }

    /// Verify machine-key attestation and optional user->agent certificate.
    pub fn verify(&self) -> error::Result<()> {
        let machine_pub =
            ant_quic::MlDsaPublicKey::from_bytes(&self.machine_public_key).map_err(|_| {
                error::IdentityError::CertificateVerification(
                    "invalid machine public key in announcement".to_string(),
                )
            })?;
        let derived_machine_id = identity::MachineId::from_public_key(&machine_pub);
        if derived_machine_id != self.machine_id {
            return Err(error::IdentityError::CertificateVerification(
                "machine_id does not match machine public key".to_string(),
            ));
        }

        let unsigned_bytes = bincode::serialize(&self.to_unsigned()).map_err(|e| {
            error::IdentityError::Serialization(format!(
                "failed to serialize announcement for verification: {e}"
            ))
        })?;
        let signature = ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(
            &self.machine_signature,
        )
        .map_err(|e| {
            error::IdentityError::CertificateVerification(format!(
                "invalid machine signature in announcement: {:?}",
                e
            ))
        })?;
        ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
            &machine_pub,
            &unsigned_bytes,
            &signature,
        )
        .map_err(|e| {
            error::IdentityError::CertificateVerification(format!(
                "machine signature verification failed: {:?}",
                e
            ))
        })?;

        match (self.user_id, self.agent_certificate.as_ref()) {
            (Some(user_id), Some(cert)) => {
                cert.verify()?;
                let cert_agent_id = cert.agent_id()?;
                if cert_agent_id != self.agent_id {
                    return Err(error::IdentityError::CertificateVerification(
                        "agent certificate agent_id mismatch".to_string(),
                    ));
                }
                let cert_user_id = cert.user_id()?;
                if cert_user_id != user_id {
                    return Err(error::IdentityError::CertificateVerification(
                        "agent certificate user_id mismatch".to_string(),
                    ));
                }
                Ok(())
            }
            (None, None) => Ok(()),
            _ => Err(error::IdentityError::CertificateVerification(
                "user identity disclosure requires matching certificate".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MachineAnnouncementUnsigned {
    machine_id: identity::MachineId,
    machine_public_key: Vec<u8>,
    addresses: Vec<std::net::SocketAddr>,
    announced_at: u64,
    /// NAT type string (e.g. "FullCone", "Symmetric", "Unknown").
    nat_type: Option<String>,
    /// Whether the machine can receive direct inbound connections.
    can_receive_direct: Option<bool>,
    /// Whether the machine advertises relay service capability to peers.
    is_relay: Option<bool>,
    /// Whether the machine advertises coordinator capability to peers.
    is_coordinator: Option<bool>,
    /// Coordinator machines through which this machine is reachable.
    reachable_via: Vec<identity::MachineId>,
    /// Relay machines the advertising machine proposes as fallback paths.
    relay_candidates: Vec<identity::MachineId>,
}

/// Signed machine endpoint announcement.
///
/// This is the transport-level discovery record: it says "machine X is
/// reachable at these IPv4/IPv6 endpoints, with these NAT/relay/coordinator
/// hints". Agent and user identities link to this machine separately through
/// signed identity announcements.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MachineAnnouncement {
    /// Machine identity for the daemon process.
    pub machine_id: identity::MachineId,
    /// Machine ML-DSA-65 public key bytes.
    pub machine_public_key: Vec<u8>,
    /// Machine ML-DSA-65 signature over the unsigned announcement.
    pub machine_signature: Vec<u8>,
    /// Reachability hints.
    pub addresses: Vec<std::net::SocketAddr>,
    /// Unix timestamp (seconds) of announcement creation.
    pub announced_at: u64,
    /// NAT type as detected by the network layer (e.g. "FullCone", "Symmetric").
    /// `None` when the network is not yet started or NAT type is undetermined.
    pub nat_type: Option<String>,
    /// Whether the machine can receive direct inbound connections.
    /// `None` when the network is not yet started.
    pub can_receive_direct: Option<bool>,
    /// Whether the machine advertises relay service capability to peers.
    pub is_relay: Option<bool>,
    /// Whether the machine advertises coordinator capability to peers.
    pub is_coordinator: Option<bool>,
    /// Coordinator machines through which this machine is reachable.
    ///
    /// Populated when the machine is behind NAT that blocks direct inbound
    /// connections. Callers should dial one of these coordinators first,
    /// then hole-punch via peer-ID traversal.
    pub reachable_via: Vec<identity::MachineId>,
    /// Relay machines this machine proposes as fallback paths.
    pub relay_candidates: Vec<identity::MachineId>,
}

impl MachineAnnouncement {
    fn to_unsigned(&self) -> MachineAnnouncementUnsigned {
        MachineAnnouncementUnsigned {
            machine_id: self.machine_id,
            machine_public_key: self.machine_public_key.clone(),
            addresses: self.addresses.clone(),
            announced_at: self.announced_at,
            nat_type: self.nat_type.clone(),
            can_receive_direct: self.can_receive_direct,
            is_relay: self.is_relay,
            is_coordinator: self.is_coordinator,
            reachable_via: self.reachable_via.clone(),
            relay_candidates: self.relay_candidates.clone(),
        }
    }

    /// Verify the machine-key attestation for this endpoint announcement.
    pub fn verify(&self) -> error::Result<()> {
        let machine_pub =
            ant_quic::MlDsaPublicKey::from_bytes(&self.machine_public_key).map_err(|_| {
                error::IdentityError::CertificateVerification(
                    "invalid machine public key in machine announcement".to_string(),
                )
            })?;
        let derived_machine_id = identity::MachineId::from_public_key(&machine_pub);
        if derived_machine_id != self.machine_id {
            return Err(error::IdentityError::CertificateVerification(
                "machine_id does not match machine public key".to_string(),
            ));
        }

        let unsigned_bytes = bincode::serialize(&self.to_unsigned()).map_err(|e| {
            error::IdentityError::Serialization(format!(
                "failed to serialize machine announcement for verification: {e}"
            ))
        })?;
        let signature = ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(
            &self.machine_signature,
        )
        .map_err(|e| {
            error::IdentityError::CertificateVerification(format!(
                "invalid machine signature in machine announcement: {:?}",
                e
            ))
        })?;
        ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
            &machine_pub,
            &unsigned_bytes,
            &signature,
        )
        .map_err(|e| {
            error::IdentityError::CertificateVerification(format!(
                "machine announcement signature verification failed: {:?}",
                e
            ))
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct UserAnnouncementUnsigned {
    user_id: identity::UserId,
    user_public_key: Vec<u8>,
    /// Certificates the user issued binding `UserId` to each of their agents.
    ///
    /// Recipients verify each certificate's ML-DSA-65 signature and that
    /// `certificate.user_id()` matches `user_id` in this announcement.
    agent_certificates: Vec<identity::AgentCertificate>,
    announced_at: u64,
}

/// Signed user announcement broadcast on [`USER_ANNOUNCE_TOPIC`].
///
/// Published by a human operator (via `Agent::announce_user_identity`) to
/// assert first-class ownership of a set of agents, independent of whether
/// any given agent has disclosed its user binding in its own heartbeat.
/// Each [`identity::AgentCertificate`] is itself user-signed, so recipients
/// can validate every agent-owner claim without trusting the enclosing
/// announcement's producer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserAnnouncement {
    /// Human identity.
    pub user_id: identity::UserId,
    /// User's ML-DSA-65 public key bytes.
    pub user_public_key: Vec<u8>,
    /// User ML-DSA-65 signature over the unsigned announcement.
    pub user_signature: Vec<u8>,
    /// Agent certificates issued by this user.
    pub agent_certificates: Vec<identity::AgentCertificate>,
    /// Unix timestamp (seconds) of announcement creation.
    pub announced_at: u64,
}

impl UserAnnouncement {
    fn to_unsigned(&self) -> UserAnnouncementUnsigned {
        UserAnnouncementUnsigned {
            user_id: self.user_id,
            user_public_key: self.user_public_key.clone(),
            agent_certificates: self.agent_certificates.clone(),
            announced_at: self.announced_at,
        }
    }

    /// Sign an announcement binding the given user keypair to the provided
    /// agent certificates. Each certificate must already have been issued by
    /// this user — verification fails for any cert whose `user_id()` differs.
    ///
    /// # Errors
    ///
    /// Returns an error if the user public key cannot be extracted, signing
    /// fails, or any certificate was issued by a different user.
    pub fn sign(
        user_kp: &identity::UserKeypair,
        agent_certificates: Vec<identity::AgentCertificate>,
        announced_at: u64,
    ) -> error::Result<Self> {
        let user_id = user_kp.user_id();
        // Reject certificates from a different user up front — silent drop
        // would hide a configuration bug.
        for cert in &agent_certificates {
            let cert_user = cert.user_id()?;
            if cert_user != user_id {
                return Err(error::IdentityError::CertificateVerification(
                    "user announcement contains certificate issued by a different user".to_string(),
                ));
            }
        }

        let user_public_key = user_kp.public_key().as_bytes().to_vec();
        let unsigned = UserAnnouncementUnsigned {
            user_id,
            user_public_key: user_public_key.clone(),
            agent_certificates: agent_certificates.clone(),
            announced_at,
        };
        let unsigned_bytes = bincode::serialize(&unsigned).map_err(|e| {
            error::IdentityError::Serialization(format!(
                "failed to serialize unsigned user announcement: {e}"
            ))
        })?;
        let user_signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            user_kp.secret_key(),
            &unsigned_bytes,
        )
        .map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!(
                "failed to sign user announcement with user key: {e:?}"
            )))
        })?
        .as_bytes()
        .to_vec();

        Ok(Self {
            user_id,
            user_public_key,
            user_signature,
            agent_certificates,
            announced_at,
        })
    }

    /// Verify the user signature and every embedded `AgentCertificate`.
    ///
    /// Checks:
    /// 1. `user_id` matches SHA-256 of `user_public_key`.
    /// 2. Outer ML-DSA-65 signature over the canonical unsigned form.
    /// 3. For each certificate: its signature verifies and its `user_id()`
    ///    equals this announcement's `user_id`.
    ///
    /// # Errors
    ///
    /// Returns an error describing which check failed.
    pub fn verify(&self) -> error::Result<()> {
        let user_pub =
            ant_quic::MlDsaPublicKey::from_bytes(&self.user_public_key).map_err(|_| {
                error::IdentityError::CertificateVerification(
                    "invalid user public key in user announcement".to_string(),
                )
            })?;
        let derived_user_id = identity::UserId::from_public_key(&user_pub);
        if derived_user_id != self.user_id {
            return Err(error::IdentityError::CertificateVerification(
                "user_id does not match user public key in user announcement".to_string(),
            ));
        }

        let unsigned_bytes = bincode::serialize(&self.to_unsigned()).map_err(|e| {
            error::IdentityError::Serialization(format!(
                "failed to serialize user announcement for verification: {e}"
            ))
        })?;
        let signature = ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(
            &self.user_signature,
        )
        .map_err(|e| {
            error::IdentityError::CertificateVerification(format!(
                "invalid user signature in user announcement: {e:?}"
            ))
        })?;
        ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
            &user_pub,
            &unsigned_bytes,
            &signature,
        )
        .map_err(|e| {
            error::IdentityError::CertificateVerification(format!(
                "user announcement signature verification failed: {e:?}"
            ))
        })?;

        for cert in &self.agent_certificates {
            cert.verify()?;
            let cert_user = cert.user_id()?;
            if cert_user != self.user_id {
                return Err(error::IdentityError::CertificateVerification(
                    "user announcement certificate user_id mismatch".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Cached discovery data derived from [`UserAnnouncement`]s.
#[derive(Debug, Clone)]
pub struct DiscoveredUser {
    /// Human identity.
    pub user_id: identity::UserId,
    /// Raw ML-DSA-65 user public key bytes from the last verified announcement.
    pub user_public_key: Vec<u8>,
    /// Certificates the user has asserted ownership of.
    pub agent_certificates: Vec<identity::AgentCertificate>,
    /// Convenience list of agent IDs derived from the certificates.
    pub agent_ids: Vec<identity::AgentId>,
    /// Announcement timestamp from the sender.
    pub announced_at: u64,
    /// Local timestamp (seconds) when this record was last updated.
    pub last_seen: u64,
}

impl DiscoveredUser {
    fn from_announcement(announcement: &UserAnnouncement, last_seen: u64) -> Self {
        let agent_ids: Vec<identity::AgentId> = announcement
            .agent_certificates
            .iter()
            .filter_map(|c| c.agent_id().ok())
            .collect();
        Self {
            user_id: announcement.user_id,
            user_public_key: announcement.user_public_key.clone(),
            agent_certificates: announcement.agent_certificates.clone(),
            agent_ids,
            announced_at: announcement.announced_at,
            last_seen,
        }
    }
}

/// Cached discovery data derived from identity announcements.
#[derive(Debug, Clone)]
pub struct DiscoveredAgent {
    /// Portable agent identity.
    pub agent_id: identity::AgentId,
    /// Machine identity.
    pub machine_id: identity::MachineId,
    /// Optional human identity (when consented and attested).
    pub user_id: Option<identity::UserId>,
    /// Reachability hints.
    pub addresses: Vec<std::net::SocketAddr>,
    /// Announcement timestamp from the sender.
    pub announced_at: u64,
    /// Local timestamp (seconds) when this record was last updated.
    pub last_seen: u64,
    /// Raw ML-DSA-65 machine public key bytes from the announcement.
    ///
    /// Used to verify rendezvous `ProviderSummary` signatures before
    /// trusting addresses received via the rendezvous shard topic.
    #[doc(hidden)]
    pub machine_public_key: Vec<u8>,
    /// NAT type reported by this agent (e.g. "FullCone", "Symmetric", "Unknown").
    /// `None` if the agent did not include NAT information.
    pub nat_type: Option<String>,
    /// Whether this agent's machine can receive direct inbound connections.
    /// `None` if not reported.
    pub can_receive_direct: Option<bool>,
    /// Whether this agent's machine advertises relay service capability.
    /// `None` if not reported.
    pub is_relay: Option<bool>,
    /// Whether this agent's machine advertises coordinator capability.
    /// `None` if not reported.
    pub is_coordinator: Option<bool>,
    /// Coordinator machines through which this agent advertises itself as
    /// reachable when behind NAT that blocks direct inbound connections.
    pub reachable_via: Vec<identity::MachineId>,
    /// Relay machines this agent proposes as fallback paths.
    pub relay_candidates: Vec<identity::MachineId>,
    /// Expiry timestamp from the agent certificate embedded in the
    /// identity announcement, if any.  `None` means the cert carries no
    /// expiry — the agent is considered valid indefinitely.
    pub cert_not_after: Option<u64>,
    /// The agent certificate embedded in the identity announcement, if any.
    ///
    /// Retained so a gossiped **issuer-revocation** (a user un-vouching this
    /// agent) can be authority-verified on receipt: `verify_authority` for an
    /// issuer-revocation requires the subject cert (issue #191). `None` for
    /// pre-#130 peers that announce no cert, and for machine/rendezvous-only
    /// cache entries.
    pub agent_certificate: Option<identity::AgentCertificate>,
}

/// Cached machine endpoint data derived from signed machine announcements.
#[derive(Debug, Clone)]
pub struct DiscoveredMachine {
    /// Machine identity, identical to the ant-quic `PeerId`.
    pub machine_id: identity::MachineId,
    /// Reachability hints for this machine.
    pub addresses: Vec<std::net::SocketAddr>,
    /// Announcement timestamp from the sender.
    pub announced_at: u64,
    /// Local timestamp (seconds) when this record was last updated.
    pub last_seen: u64,
    /// Raw ML-DSA-65 machine public key bytes from the announcement.
    pub machine_public_key: Vec<u8>,
    /// NAT type reported by this machine.
    pub nat_type: Option<String>,
    /// Whether this machine can receive direct inbound connections.
    pub can_receive_direct: Option<bool>,
    /// Whether this machine advertises relay service capability.
    pub is_relay: Option<bool>,
    /// Whether this machine advertises coordinator capability.
    pub is_coordinator: Option<bool>,
    /// Coordinator machines through which this machine advertises itself as
    /// reachable when it cannot receive direct inbound connections.
    pub reachable_via: Vec<identity::MachineId>,
    /// Relay machines this machine proposes as fallback paths.
    pub relay_candidates: Vec<identity::MachineId>,
    /// Agent identities currently linked to this machine.
    pub agent_ids: Vec<identity::AgentId>,
    /// Human identities currently linked to this machine by consented agent
    /// announcements.
    pub user_ids: Vec<identity::UserId>,
}

/// Build a `subject AgentId → AgentCertificate` lookup from the discovery
/// cache, used to authority-verify gossiped **issuer-revocations** (a user
/// un-vouching a certified agent) on receipt (issue #191).
///
/// `verify_authority` for an issuer-revocation requires the subject agent's
/// certificate; self-revocations and machine-revocations need none. Only
/// entries that actually carry a cert contribute; entries without one
/// (pre-#130 peers, machine/rendezvous-only entries) are absent, so an
/// issuer-revocation for such a subject is rejected fail-closed by the
/// caller — the cert must have been announced first (EP1).
fn collect_subject_certs(
    cache: &std::collections::HashMap<identity::AgentId, DiscoveredAgent>,
) -> std::collections::HashMap<identity::AgentId, identity::AgentCertificate> {
    cache
        .values()
        .filter_map(|a| {
            a.agent_certificate
                .as_ref()
                .map(|c| (a.agent_id, c.clone()))
        })
        .collect()
}

impl DiscoveredMachine {
    fn from_machine_announcement(
        announcement: &MachineAnnouncement,
        addresses: Vec<std::net::SocketAddr>,
        last_seen: u64,
    ) -> Self {
        Self {
            machine_id: announcement.machine_id,
            addresses,
            announced_at: announcement.announced_at,
            last_seen,
            machine_public_key: announcement.machine_public_key.clone(),
            nat_type: announcement.nat_type.clone(),
            can_receive_direct: announcement.can_receive_direct,
            is_relay: announcement.is_relay,
            is_coordinator: announcement.is_coordinator,
            reachable_via: announcement.reachable_via.clone(),
            relay_candidates: announcement.relay_candidates.clone(),
            agent_ids: Vec::new(),
            user_ids: Vec::new(),
        }
    }

    fn from_discovered_agent(agent: &DiscoveredAgent) -> Self {
        Self {
            machine_id: agent.machine_id,
            addresses: agent.addresses.clone(),
            announced_at: agent.announced_at,
            last_seen: agent.last_seen,
            machine_public_key: agent.machine_public_key.clone(),
            nat_type: agent.nat_type.clone(),
            can_receive_direct: agent.can_receive_direct,
            is_relay: agent.is_relay,
            is_coordinator: agent.is_coordinator,
            reachable_via: agent.reachable_via.clone(),
            relay_candidates: agent.relay_candidates.clone(),
            agent_ids: vec![agent.agent_id],
            user_ids: agent.user_id.into_iter().collect(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AnnouncementAssistSnapshot {
    nat_type: Option<String>,
    can_receive_direct: Option<bool>,
    relay_capable: Option<bool>,
    coordinator_capable: Option<bool>,
    relay_active: Option<bool>,
    coordinator_active: Option<bool>,
}

impl AnnouncementAssistSnapshot {
    fn from_node_status(status: &ant_quic::NodeStatus) -> Self {
        Self {
            nat_type: Some(status.nat_type.to_string()),
            can_receive_direct: Some(status.can_receive_direct),
            relay_capable: Some(status.relay_service_enabled),
            coordinator_capable: Some(status.coordinator_service_enabled),
            relay_active: Some(status.is_relaying),
            coordinator_active: Some(status.is_coordinating),
        }
    }
}

struct IdentityAnnouncementBuildOptions<'a> {
    include_user_identity: bool,
    human_consent: bool,
    addresses: Vec<std::net::SocketAddr>,
    assist_snapshot: Option<&'a AnnouncementAssistSnapshot>,
    reachable_via: Vec<identity::MachineId>,
    relay_candidates: Vec<identity::MachineId>,
    allow_local_scope: bool,
}

fn push_unique<T: Copy + PartialEq>(items: &mut Vec<T>, item: T) {
    if !items.contains(&item) {
        items.push(item);
    }
}

fn prioritize_discovery_addresses(addresses: &mut [std::net::SocketAddr]) {
    addresses.sort_by_key(|addr| is_publicly_advertisable(*addr));
}

/// Merge a freshly-discovered agent announcement into the cache.
///
/// Per-field precedence is keyed on `announced_at` (the signed announcement's
/// own monotonic timestamp), not local receive time:
/// - **addresses** reflect the agent's *current* advertised set. A fresher (or
///   equal) announcement REPLACES the cached list; a stale announcement leaves
///   it untouched. Announcements carry the agent's full address set, so
///   replacing — not unioning — keeps the list bounded: a roaming agent
///   (Wi-Fi → cellular → VPN) does not accumulate dead endpoints, each of which
///   would otherwise cost a dial timeout in `connect_to_*` / `direct_probe`.
/// - **machine_id / public key / nat / capability / relay hints** update only
///   from a fresher-or-equal announcement, and only when present — a zeroed
///   machine_id or empty key never clobbers a known value.
/// - **user_id** is never erased: a fresher *anonymous* announcement keeps a
///   previously-disclosed user_id.
/// - **last_seen** reflects the most recent receive: it is set from the
///   incoming record (matching the pre-merge replace semantics). In production
///   `incoming.last_seen` is the current receive time, so it only moves forward;
///   it is NOT clamped with `max`, because the TTL/presence filter must be able
///   to observe an entry that has genuinely aged past its window (a `max` clamp
///   would let a once-fresh entry mask a later stale observation and never
///   expire — see `test_ttl_expiry_removes_from_presence`).
async fn upsert_discovered_agent(
    cache: &std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<identity::AgentId, DiscoveredAgent>>,
    >,
    mut incoming: DiscoveredAgent,
) {
    prioritize_discovery_addresses(&mut incoming.addresses);
    let mut cache = cache.write().await;
    match cache.get_mut(&incoming.agent_id) {
        Some(existing) => {
            if incoming.announced_at >= existing.announced_at {
                existing.announced_at = incoming.announced_at;
                // Replace, don't union: the announcement carries the agent's
                // full current address set, so the cached list stays bounded.
                existing.addresses = incoming.addresses;
                prioritize_discovery_addresses(&mut existing.addresses);
                if incoming.machine_id.0 != [0u8; 32] {
                    existing.machine_id = incoming.machine_id;
                }
                if incoming.user_id.is_some() || existing.user_id.is_none() {
                    existing.user_id = incoming.user_id;
                }
                if !incoming.machine_public_key.is_empty() {
                    existing.machine_public_key = incoming.machine_public_key;
                }
                if incoming.nat_type.is_some() {
                    existing.nat_type = incoming.nat_type;
                }
                if incoming.can_receive_direct.is_some() {
                    existing.can_receive_direct = incoming.can_receive_direct;
                }
                if incoming.is_relay.is_some() {
                    existing.is_relay = incoming.is_relay;
                }
                if incoming.is_coordinator.is_some() {
                    existing.is_coordinator = incoming.is_coordinator;
                }
                existing.reachable_via = incoming.reachable_via;
                existing.relay_candidates = incoming.relay_candidates;
            }
            existing.last_seen = incoming.last_seen;
        }
        None => {
            cache.insert(incoming.agent_id, incoming);
        }
    }
}

fn sort_discovered_machine(machine: &mut DiscoveredMachine) {
    machine.addresses.sort_by_key(|addr| addr.to_string());
    machine.agent_ids.sort_by_key(|id| id.0);
    machine.user_ids.sort_by_key(|id| id.0);
    machine.reachable_via.sort_by_key(|id| id.0);
    machine.relay_candidates.sort_by_key(|id| id.0);
}

async fn upsert_discovered_machine(
    cache: &std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<identity::MachineId, DiscoveredMachine>>,
    >,
    mut incoming: DiscoveredMachine,
) {
    if incoming.machine_id.0 == [0u8; 32] {
        return;
    }

    sort_discovered_machine(&mut incoming);
    let mut cache = cache.write().await;
    match cache.get_mut(&incoming.machine_id) {
        Some(existing) => {
            for addr in incoming.addresses {
                if !existing.addresses.contains(&addr) {
                    existing.addresses.push(addr);
                }
            }
            if incoming.announced_at >= existing.announced_at {
                existing.announced_at = incoming.announced_at;
                if !incoming.machine_public_key.is_empty() {
                    existing.machine_public_key = incoming.machine_public_key;
                }
                if incoming.nat_type.is_some() {
                    existing.nat_type = incoming.nat_type;
                }
                if incoming.can_receive_direct.is_some() {
                    existing.can_receive_direct = incoming.can_receive_direct;
                }
                if incoming.is_relay.is_some() {
                    existing.is_relay = incoming.is_relay;
                }
                if incoming.is_coordinator.is_some() {
                    existing.is_coordinator = incoming.is_coordinator;
                }
                // Coordinator / relay hint lists are LWW: the newest
                // announcement knows best whether its set has shrunk
                // (e.g. a coordinator peer just disconnected).
                existing.reachable_via = incoming.reachable_via;
                existing.relay_candidates = incoming.relay_candidates;
            }
            existing.last_seen = existing.last_seen.max(incoming.last_seen);
            for agent_id in incoming.agent_ids {
                push_unique(&mut existing.agent_ids, agent_id);
            }
            for user_id in incoming.user_ids {
                push_unique(&mut existing.user_ids, user_id);
            }
            sort_discovered_machine(existing);
        }
        None => {
            cache.insert(incoming.machine_id, incoming);
        }
    }
}

async fn upsert_discovered_machine_from_agent(
    cache: &std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<identity::MachineId, DiscoveredMachine>>,
    >,
    agent: &DiscoveredAgent,
) {
    if agent.machine_id.0 != [0u8; 32] {
        upsert_discovered_machine(cache, DiscoveredMachine::from_discovered_agent(agent)).await;
    }
}

const MAX_MACHINE_ANNOUNCEMENT_DECODE_BYTES: u64 = 64 * 1024;

fn deserialize_identity_announcement(
    payload: &[u8],
) -> std::result::Result<IdentityAnnouncement, Box<bincode::ErrorKind>> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(crate::network::MAX_MESSAGE_DESERIALIZE_SIZE)
        .reject_trailing_bytes()
        .deserialize(payload)
}

fn deserialize_user_announcement(
    payload: &[u8],
) -> std::result::Result<UserAnnouncement, Box<bincode::ErrorKind>> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(crate::network::MAX_MESSAGE_DESERIALIZE_SIZE)
        .reject_trailing_bytes()
        .deserialize(payload)
}

fn deserialize_machine_announcement(
    payload: &[u8],
) -> std::result::Result<MachineAnnouncement, Box<bincode::ErrorKind>> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_MACHINE_ANNOUNCEMENT_DECODE_BYTES)
        .reject_trailing_bytes()
        .deserialize(payload)
}

/// Compute coordinator / relay hint lists for an announcement.
///
/// Collects machine IDs of currently-connected peers that the machine cache
/// marks as coordinator- or relay-capable. Deduplicated, capped to
/// `MAX_COORDINATOR_HINTS` each, and returned in stable order.
///
/// Used to populate `reachable_via` / `relay_candidates` on outgoing
/// announcements so that remote peers have concrete targets to dial when
/// the advertising machine is NAT-locked.
async fn collect_coordinator_hints(
    network: &network::NetworkNode,
    machine_cache: &std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<identity::MachineId, DiscoveredMachine>>,
    >,
    own_machine_id: identity::MachineId,
) -> (Vec<identity::MachineId>, Vec<identity::MachineId>) {
    /// Upper bound on hint list length. Keeps the signed payload small and
    /// avoids amplifying gossip if we accumulate many peers.
    const MAX_COORDINATOR_HINTS: usize = 8;

    let connected = network.connected_peers().await;
    if connected.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let cache = machine_cache.read().await;
    let mut reachable_via: Vec<identity::MachineId> = Vec::new();
    let mut relay_candidates: Vec<identity::MachineId> = Vec::new();

    for peer_id in connected {
        let mid = identity::MachineId(peer_id.0);
        if mid == own_machine_id {
            continue;
        }
        let Some(entry) = cache.get(&mid) else {
            continue;
        };
        if entry.is_coordinator == Some(true)
            && !reachable_via.contains(&mid)
            && reachable_via.len() < MAX_COORDINATOR_HINTS
        {
            reachable_via.push(mid);
        }
        if entry.is_relay == Some(true)
            && !relay_candidates.contains(&mid)
            && relay_candidates.len() < MAX_COORDINATOR_HINTS
        {
            relay_candidates.push(mid);
        }
    }

    reachable_via.sort_by_key(|id| id.0);
    relay_candidates.sort_by_key(|id| id.0);
    (reachable_via, relay_candidates)
}

fn build_machine_announcement_for_identity(
    identity: &identity::Identity,
    addresses: Vec<std::net::SocketAddr>,
    announced_at: u64,
    assist_snapshot: Option<&AnnouncementAssistSnapshot>,
    reachable_via: Vec<identity::MachineId>,
    relay_candidates: Vec<identity::MachineId>,
    allow_local_scope: bool,
) -> error::Result<MachineAnnouncement> {
    let addresses = filter_discovery_announcement_addrs(addresses, allow_local_scope);
    let machine_public_key = identity.machine_keypair().public_key().as_bytes().to_vec();
    let unsigned = MachineAnnouncementUnsigned {
        machine_id: identity.machine_id(),
        machine_public_key: machine_public_key.clone(),
        addresses,
        announced_at,
        nat_type: assist_snapshot.and_then(|snapshot| snapshot.nat_type.clone()),
        can_receive_direct: assist_snapshot.and_then(|snapshot| snapshot.can_receive_direct),
        is_relay: assist_snapshot.and_then(|snapshot| snapshot.relay_capable),
        is_coordinator: assist_snapshot.and_then(|snapshot| snapshot.coordinator_capable),
        reachable_via,
        relay_candidates,
    };
    let unsigned_bytes = bincode::serialize(&unsigned).map_err(|e| {
        error::IdentityError::Serialization(format!(
            "failed to serialize unsigned machine announcement: {e}"
        ))
    })?;
    let machine_signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
        identity.machine_keypair().secret_key(),
        &unsigned_bytes,
    )
    .map_err(|e| {
        error::IdentityError::Storage(std::io::Error::other(format!(
            "failed to sign machine announcement with machine key: {:?}",
            e
        )))
    })?
    .as_bytes()
    .to_vec();

    Ok(MachineAnnouncement {
        machine_id: unsigned.machine_id,
        machine_public_key,
        machine_signature,
        addresses: unsigned.addresses,
        announced_at: unsigned.announced_at,
        nat_type: unsigned.nat_type,
        can_receive_direct: unsigned.can_receive_direct,
        is_relay: unsigned.is_relay,
        is_coordinator: unsigned.is_coordinator,
        reachable_via: unsigned.reachable_via,
        relay_candidates: unsigned.relay_candidates,
    })
}

/// Builder for configuring an [`Agent`] before connecting to the network.
///
/// The builder allows customization of the agent's identity:
/// - Machine key path: Where to store/load the machine keypair
/// - Agent keypair: Import a portable agent identity from another machine
/// - User keypair: Bind a human identity to this agent
///
/// # Example
///
/// ```ignore
/// use x0x::Agent;
///
/// // Default: auto-generates both keypairs
/// let agent = Agent::builder()
///     .build()
///     .await?;
///
/// // Custom machine key path
/// let agent = Agent::builder()
///     .with_machine_key("/custom/path/machine.key")
///     .build()
///     .await?;
///
/// // Import agent keypair
/// let agent_kp = load_agent_keypair()?;
/// let agent = Agent::builder()
///     .with_agent_key(agent_kp)
///     .build()
///     .await?;
///
/// // With user identity (three-layer)
/// let agent = Agent::builder()
///     .with_user_key_path("~/.x0x/user.key")
///     .build()
///     .await?;
/// ```
#[derive(Debug)]
pub struct AgentBuilder {
    machine_key_path: Option<std::path::PathBuf>,
    agent_keypair: Option<identity::AgentKeypair>,
    agent_key_path: Option<std::path::PathBuf>,
    /// Custom path for `agent.cert`. When set, the cert is loaded/saved from
    /// this path instead of `~/.x0x/agent.cert`. Required for multi-daemon
    /// setups on the same host — with a shared cert file, last-writer-wins
    /// trampling would cause the victim daemon to announce its own agent_id
    /// paired with another daemon's cert, and peers would reject as
    /// "agent certificate agent_id mismatch".
    agent_cert_path: Option<std::path::PathBuf>,
    user_keypair: Option<identity::UserKeypair>,
    user_key_path: Option<std::path::PathBuf>,
    #[allow(dead_code)]
    network_config: Option<network::NetworkConfig>,
    gossip_config: Option<gossip::GossipConfig>,
    peer_cache_dir: Option<std::path::PathBuf>,
    /// When true, skip opening the bootstrap peer cache entirely.
    /// Useful for fully isolated embedders and test harnesses.
    disable_peer_cache: bool,
    heartbeat_interval_secs: Option<u64>,
    identity_ttl_secs: Option<u64>,
    presence_beacon_interval_secs: Option<u64>,
    presence_event_poll_interval_secs: Option<u64>,
    presence_offline_timeout_secs: Option<u64>,
    /// Custom path for the contacts file.
    contact_store_path: Option<std::path::PathBuf>,
    /// Directory that scopes all identity-related files (keys, cert,
    /// revocations.bin).  When set, revocations are loaded/saved there
    /// instead of the default `~/.x0x/` directory.
    identity_dir: Option<std::path::PathBuf>,
}

/// Context captured by the background identity heartbeat task.
struct HeartbeatContext {
    identity: std::sync::Arc<identity::Identity>,
    runtime: std::sync::Arc<gossip::GossipRuntime>,
    network: std::sync::Arc<network::NetworkNode>,
    interval_secs: u64,
    cache: std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<identity::AgentId, DiscoveredAgent>>,
    >,
    machine_cache: std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<identity::MachineId, DiscoveredMachine>>,
    >,
    /// Whether the user has consented to identity disclosure.  When true,
    /// heartbeats include `user_id` and `agent_certificate` so they don't
    /// erase a consented disclosure.
    user_identity_consented: std::sync::Arc<std::sync::atomic::AtomicBool>,
    allow_local_discovery_addrs: bool,
    /// Local revocation set — piggybacked on each heartbeat for partition-
    /// tolerant eventual propagation.
    revocation_set: std::sync::Arc<tokio::sync::RwLock<revocation::RevocationSet>>,
}

impl HeartbeatContext {
    async fn announce(&self) -> error::Result<()> {
        let machine_public_key = self
            .identity
            .machine_keypair()
            .public_key()
            .as_bytes()
            .to_vec();
        let announced_at = Agent::unix_timestamp_secs();

        // Include ALL routable addresses (IPv4 and IPv6) so other agents
        // can connect to us via whichever protocol they support.
        let mut addresses = match self.network.node_status().await {
            Some(status) if !status.external_addrs.is_empty() => status.external_addrs,
            _ => match self.network.routable_addr().await {
                Some(addr) => vec![addr],
                None => Vec::new(),
            },
        };

        // Detect global IPv6 address locally (ant-quic currently only
        // reports IPv4 via OBSERVED_ADDRESS). Uses UDP connect trick —
        // no data is sent, the OS routing table resolves our source addr.
        //
        // For locally-probed addresses (IPv6 and LAN IPv4), use the actual
        // bound port from the QUIC endpoint — NOT the first external address
        // port (which is NAT-mapped) and NOT the config bind port (which may
        // be 0 for OS-assigned ports).
        let bind_port = self
            .network
            .bound_addr()
            .await
            .map(|a| a.port())
            .unwrap_or(5483);
        if let Ok(sock) = std::net::UdpSocket::bind("[::]:0") {
            if sock.connect("[2001:4860:4860::8888]:80").is_ok() {
                if let Ok(local) = sock.local_addr() {
                    if let std::net::IpAddr::V6(v6) = local.ip() {
                        let segs = v6.segments();
                        let is_global = (segs[0] & 0xffc0) != 0xfe80
                            && (segs[0] & 0xff00) != 0xfd00
                            && !v6.is_loopback();
                        if is_global {
                            let v6_addr =
                                std::net::SocketAddr::new(std::net::IpAddr::V6(v6), bind_port);
                            if !addresses.contains(&v6_addr) {
                                addresses.push(v6_addr);
                            }
                        }
                    }
                }
            }
        }

        for addr in collect_local_interface_addrs(bind_port) {
            if !addresses.contains(&addr) {
                addresses.push(addr);
            }
        }

        // Global bootstrap partitions must not ship LAN-scope addresses over
        // gossip: remote peers cannot reach them and each dead dial consumes
        // connect budget. Explicit local/testnet partitions are different; they
        // need signed LAN/loopback hints because there may be no public endpoint
        // or mDNS bridge between the isolated daemons.
        addresses =
            filter_discovery_announcement_addrs(addresses, self.allow_local_discovery_addrs);

        // Query reachability plus stable relay/coordinator capability from
        // the network layer. Runtime activity is logged separately so we do
        // not conflate "can help" with "is currently busy helping".
        let assist_snapshot = self
            .network
            .node_status()
            .await
            .map(|status| AnnouncementAssistSnapshot::from_node_status(&status))
            .unwrap_or_default();
        let nat_type = assist_snapshot.nat_type.clone();
        let can_receive_direct = assist_snapshot.can_receive_direct;
        let relay_capable = assist_snapshot.relay_capable;
        let coordinator_capable = assist_snapshot.coordinator_capable;

        // Only emit coordinator / relay hints when we believe remote peers
        // cannot reach us directly. Directly-reachable peers don't need
        // help, and advertising hints we don't need just bloats gossip.
        let (reachable_via, relay_candidates) = if can_receive_direct == Some(true) {
            (Vec::new(), Vec::new())
        } else {
            collect_coordinator_hints(
                self.network.as_ref(),
                &self.machine_cache,
                self.identity.machine_id(),
            )
            .await
        };

        // Include user identity ONLY if the user has previously consented
        // via announce_identity(true, true). This preserves the consented
        // disclosure across heartbeats without ever escalating on its own.
        let include_user = self
            .user_identity_consented
            .load(std::sync::atomic::Ordering::Acquire);
        let (user_id, agent_certificate) = if include_user {
            (
                self.identity
                    .user_keypair()
                    .map(identity::UserKeypair::user_id),
                self.identity.agent_certificate().cloned(),
            )
        } else {
            (None, None)
        };

        let unsigned = IdentityAnnouncementUnsigned {
            agent_id: self.identity.agent_id(),
            machine_id: self.identity.machine_id(),
            user_id,
            agent_certificate,
            machine_public_key: machine_public_key.clone(),
            addresses,
            announced_at,
            nat_type: nat_type.clone(),
            can_receive_direct,
            is_relay: relay_capable,
            is_coordinator: coordinator_capable,
            reachable_via: reachable_via.clone(),
            relay_candidates: relay_candidates.clone(),
        };
        let unsigned_bytes = bincode::serialize(&unsigned).map_err(|e| {
            error::IdentityError::Serialization(format!(
                "heartbeat: failed to serialize announcement: {e}"
            ))
        })?;
        let machine_signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            self.identity.machine_keypair().secret_key(),
            &unsigned_bytes,
        )
        .map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!(
                "heartbeat: failed to sign announcement: {:?}",
                e
            )))
        })?
        .as_bytes()
        .to_vec();

        let announcement = IdentityAnnouncement {
            agent_id: unsigned.agent_id,
            machine_id: unsigned.machine_id,
            user_id: unsigned.user_id,
            agent_certificate: unsigned.agent_certificate,
            machine_public_key: machine_public_key.clone(),
            machine_signature,
            addresses: unsigned.addresses,
            announced_at,
            nat_type,
            can_receive_direct,
            is_relay: relay_capable,
            is_coordinator: coordinator_capable,
            reachable_via: reachable_via.clone(),
            relay_candidates: relay_candidates.clone(),
        };
        tracing::debug!(
            target: "x0x::discovery",
            announcement_kind = "heartbeat",
            machine_prefix = %network::hex_prefix(&announcement.machine_id.0, 4),
            addr_total = announcement.addresses.len(),
            nat_type = announcement.nat_type.as_deref().unwrap_or("unknown"),
            can_receive_direct = ?announcement.can_receive_direct,
            relay_capable = ?announcement.is_relay,
            coordinator_capable = ?announcement.is_coordinator,
            relay_active = ?assist_snapshot.relay_active,
            coordinator_active = ?assist_snapshot.coordinator_active,
            reachable_via_count = announcement.reachable_via.len(),
            relay_candidate_count = announcement.relay_candidates.len(),
            "publishing identity announcement"
        );

        let machine_announcement = build_machine_announcement_for_identity(
            &self.identity,
            announcement.addresses.clone(),
            announced_at,
            Some(&assist_snapshot),
            reachable_via.clone(),
            relay_candidates.clone(),
            self.allow_local_discovery_addrs,
        )?;
        tracing::debug!(
            target: "x0x::discovery",
            announcement_kind = "machine_heartbeat",
            machine_prefix = %network::hex_prefix(&machine_announcement.machine_id.0, 4),
            addr_total = machine_announcement.addresses.len(),
            nat_type = machine_announcement.nat_type.as_deref().unwrap_or("unknown"),
            can_receive_direct = ?machine_announcement.can_receive_direct,
            relay_capable = ?machine_announcement.is_relay,
            coordinator_capable = ?machine_announcement.is_coordinator,
            "publishing machine announcement"
        );
        let machine_encoded = bincode::serialize(&machine_announcement).map_err(|e| {
            error::IdentityError::Serialization(format!(
                "heartbeat: failed to serialize machine announcement: {e}"
            ))
        })?;
        let machine_payload = bytes::Bytes::from(machine_encoded);
        self.runtime
            .pubsub()
            .publish(
                shard_topic_for_machine(&machine_announcement.machine_id),
                machine_payload.clone(),
            )
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "heartbeat: machine shard publish failed: {e}"
                )))
            })?;
        self.runtime
            .pubsub()
            .publish(MACHINE_ANNOUNCE_TOPIC.to_string(), machine_payload)
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "heartbeat: machine publish failed: {e}"
                )))
            })?;

        let encoded = bincode::serialize(&announcement).map_err(|e| {
            error::IdentityError::Serialization(format!(
                "heartbeat: failed to serialize announcement: {e}"
            ))
        })?;
        self.runtime
            .pubsub()
            .publish(
                IDENTITY_ANNOUNCE_TOPIC.to_string(),
                bytes::Bytes::from(encoded),
            )
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "heartbeat: publish failed: {e}"
                )))
            })?;
        let now = Agent::unix_timestamp_secs();
        upsert_discovered_machine(
            &self.machine_cache,
            DiscoveredMachine::from_machine_announcement(
                &machine_announcement,
                machine_announcement.addresses.clone(),
                now,
            ),
        )
        .await;
        let discovered_agent = DiscoveredAgent {
            agent_id: announcement.agent_id,
            machine_id: announcement.machine_id,
            user_id: announcement.user_id,
            addresses: announcement.addresses,
            announced_at: announcement.announced_at,
            last_seen: now,
            machine_public_key: machine_public_key.clone(),
            nat_type: announcement.nat_type.clone(),
            can_receive_direct: announcement.can_receive_direct,
            is_relay: announcement.is_relay,
            is_coordinator: announcement.is_coordinator,
            reachable_via: announcement.reachable_via.clone(),
            relay_candidates: announcement.relay_candidates.clone(),
            cert_not_after: None,
            agent_certificate: None,
        };
        upsert_discovered_machine_from_agent(&self.machine_cache, &discovered_agent).await;
        upsert_discovered_agent(&self.cache, discovered_agent).await;

        // Piggyback the local revocation set on each heartbeat for partition-
        // tolerant eventual convergence.  A node that was offline when a
        // revocation was originally published will learn it from the next
        // heartbeat it receives from any peer that already holds it.
        let records = self.revocation_set.read().await.all_records();
        if !records.is_empty() {
            match bincode::serialize(&records) {
                Ok(bytes) => {
                    if let Err(e) = self
                        .runtime
                        .pubsub()
                        .publish(REVOCATION_TOPIC.to_string(), bytes::Bytes::from(bytes))
                        .await
                    {
                        tracing::debug!("heartbeat: revocation re-broadcast failed: {e}");
                    }
                }
                Err(e) => {
                    tracing::debug!("heartbeat: failed to serialize revocation set: {e}");
                }
            }
        }

        Ok(())
    }
}

impl Agent {
    /// Create a new offline agent with default identity configuration.
    ///
    /// This generates a fresh identity with both machine and agent keypairs.
    /// The machine keypair is stored persistently in `~/.x0x/machine.key`.
    /// Network and gossip runtime setup is opt-in via
    /// [`Agent::builder()`] and [`AgentBuilder::with_network_config()`].
    ///
    /// For more control, use [`Agent::builder()`].
    pub async fn new() -> error::Result<Self> {
        Agent::builder().build().await
    }

    /// Create an [`AgentBuilder`] for fine-grained configuration.
    ///
    /// The builder supports:
    /// - Custom machine key path via `with_machine_key()`
    /// - Imported agent keypair via `with_agent_key()`
    /// - User identity via `with_user_key()` or `with_user_key_path()`
    /// - Network and gossip runtime via `with_network_config()` (opt-in)
    pub fn builder() -> AgentBuilder {
        AgentBuilder {
            machine_key_path: None,
            agent_keypair: None,
            agent_key_path: None,
            agent_cert_path: None,
            user_keypair: None,
            user_key_path: None,
            network_config: None,
            gossip_config: None,
            peer_cache_dir: None,
            disable_peer_cache: false,
            heartbeat_interval_secs: None,
            identity_ttl_secs: None,
            presence_beacon_interval_secs: None,
            presence_event_poll_interval_secs: None,
            presence_offline_timeout_secs: None,
            contact_store_path: None,
            identity_dir: None,
        }
    }

    /// Get the agent's identity.
    ///
    /// # Returns
    ///
    /// A reference to the agent's [`identity::Identity`].
    #[inline]
    #[must_use]
    pub fn identity(&self) -> &identity::Identity {
        &self.identity
    }

    /// Get the machine ID for this agent.
    ///
    /// The machine ID is tied to this computer and used for QUIC transport
    /// authentication. It is stored persistently in `~/.x0x/machine.key`.
    ///
    /// # Returns
    ///
    /// The agent's machine ID.
    #[inline]
    #[must_use]
    pub fn machine_id(&self) -> identity::MachineId {
        self.identity.machine_id()
    }

    /// Get the agent ID for this agent.
    ///
    /// The agent ID is portable across machines and represents the agent's
    /// persistent identity. It can be exported and imported to run the same
    /// agent on different computers.
    ///
    /// # Returns
    ///
    /// The agent's ID.
    #[inline]
    #[must_use]
    pub fn agent_id(&self) -> identity::AgentId {
        self.identity.agent_id()
    }

    /// Get the user ID for this agent, if a user identity is bound.
    ///
    /// Returns `None` if no user keypair was provided during construction.
    /// User keys are opt-in — they are never auto-generated.
    #[inline]
    #[must_use]
    pub fn user_id(&self) -> Option<identity::UserId> {
        self.identity.user_id()
    }

    /// Get the agent certificate, if one exists.
    ///
    /// The certificate cryptographically binds this agent to a user identity.
    #[inline]
    #[must_use]
    pub fn agent_certificate(&self) -> Option<&identity::AgentCertificate> {
        self.identity.agent_certificate()
    }

    /// Get the network node, if initialized.
    #[must_use]
    pub fn network(&self) -> Option<&std::sync::Arc<network::NetworkNode>> {
        self.network.as_ref()
    }

    /// Get the gossip cache adapter for coordinator discovery.
    ///
    /// Returns `None` if this agent was built without a network config.
    /// The adapter wraps the same `Arc<BootstrapCache>` as the network node.
    pub fn gossip_cache_adapter(&self) -> Option<&saorsa_gossip_coordinator::GossipCacheAdapter> {
        self.gossip_cache_adapter.as_ref()
    }

    /// Snapshot of pub/sub drop-detection counters.
    ///
    /// Returns `None` when the agent has no gossip runtime (e.g. offline
    /// unit tests). Exposed through `GET /diagnostics/gossip` on x0xd so
    /// that E2E harnesses can assert zero drops between publish and
    /// subscriber delivery.
    #[must_use]
    pub fn gossip_stats(&self) -> Option<gossip::PubSubStatsSnapshot> {
        self.gossip_runtime.as_ref().map(|rt| rt.pubsub().stats())
    }

    /// Snapshot of inbound gossip dispatcher counters.
    ///
    /// Returns `None` when the agent has no gossip runtime. Exposed through
    /// `GET /diagnostics/gossip` alongside pub/sub drop-detection counters so
    /// live soaks can identify slow or timed-out stream handlers.
    #[must_use]
    pub fn gossip_dispatch_stats(&self) -> Option<gossip::GossipDispatchStatsSnapshot> {
        self.gossip_runtime.as_ref().map(|rt| rt.dispatch_stats())
    }

    /// Snapshot of per-stage PubSub handling timings.
    ///
    /// Returns `None` when the agent has no gossip runtime. This is the
    /// X0X-0006 diagnostic block used to identify which stage of
    /// `PubSubManager::handle_incoming` dominates dispatcher wall-clock time.
    #[must_use]
    pub fn gossip_pubsub_stage_stats(&self) -> Option<gossip::PubSubStageStatsSnapshot> {
        self.gossip_runtime
            .as_ref()
            .map(|rt| rt.pubsub().stage_stats())
    }

    /// Snapshot of ant-quic → gossip receive-pump diagnostics.
    ///
    /// Returns `None` when this agent was built without a network node.
    /// Exposed through `GET /diagnostics/gossip` so operators can compare
    /// producer rate, consumer drain rate, queue dwell time, and overload drops.
    #[must_use]
    pub fn recv_pump_diagnostics(&self) -> Option<network::RecvPumpDiagnosticsSnapshot> {
        self.network.as_ref().map(|net| net.recv_pump_diagnostics())
    }

    /// Get the presence system wrapper, if configured.
    ///
    /// Returns `None` if this agent was built without a network config.
    /// The presence wrapper provides beacon broadcasting, FOAF discovery,
    /// and online/offline event subscriptions.
    #[must_use]
    pub fn presence_system(&self) -> Option<&std::sync::Arc<presence::PresenceWrapper>> {
        self.presence.as_ref()
    }

    /// Get a reference to the contact store.
    ///
    /// The contact store persists trust levels and machine records for known
    /// agents. It is backed by `~/.x0x/contacts.json` by default.
    ///
    /// Use [`with_contact_store_path`](AgentBuilder::with_contact_store_path)
    /// on the builder to customise the path.
    #[must_use]
    pub fn contacts(&self) -> &std::sync::Arc<tokio::sync::RwLock<contacts::ContactStore>> {
        &self.contact_store
    }

    /// Get the reachability information for a discovered agent.
    ///
    /// Returns `None` if the agent is not in the discovery cache.
    /// Use [`Agent::announce_identity`] or wait for a heartbeat announcement
    /// to populate the cache.
    pub async fn reachability(
        &self,
        agent_id: &identity::AgentId,
    ) -> Option<connectivity::ReachabilityInfo> {
        let cache = self.identity_discovery_cache.read().await;
        cache
            .get(agent_id)
            .map(connectivity::ReachabilityInfo::from_discovered)
    }

    async fn seed_transport_peer_hints_for_target(
        &self,
        network: &network::NetworkNode,
        target: &DiscoveredAgent,
    ) -> error::Result<()> {
        #[derive(Default)]
        struct HelperHintEntry {
            addrs: Vec<std::net::SocketAddr>,
            caps: ant_quic::bootstrap_cache::PeerCapabilities,
            sources: std::collections::BTreeSet<&'static str>,
        }

        fn merge_helper_hint(
            hints: &mut std::collections::HashMap<ant_quic::PeerId, HelperHintEntry>,
            peer_id: ant_quic::PeerId,
            source: &'static str,
            addrs: impl IntoIterator<Item = std::net::SocketAddr>,
            supports_coordination: bool,
            supports_relay: bool,
        ) {
            let entry = hints.entry(peer_id).or_default();
            entry.sources.insert(source);
            for addr in addrs {
                if !entry.addrs.contains(&addr) {
                    entry.addrs.push(addr);
                }
            }
            if supports_coordination {
                entry.caps.supports_coordination = true;
            }
            if supports_relay {
                entry.caps.supports_relay = true;
            }
        }

        let target_agent_prefix = network::hex_prefix(&target.agent_id.0, 4);
        let target_machine_prefix = network::hex_prefix(&target.machine_id.0, 4);
        let target_peer_id = ant_quic::PeerId(target.machine_id.0);
        if target.machine_id.0 != [0u8; 32] {
            network
                .upsert_peer_hints(target_peer_id, target.addresses.clone(), None)
                .await
                .map_err(|e| {
                    error::IdentityError::Storage(std::io::Error::other(format!(
                        "failed to upsert target peer hints: {e}"
                    )))
                })?;
            tracing::debug!(
                target: "x0x::connect",
                stage = "seed_target_hints",
                %target_agent_prefix,
                %target_machine_prefix,
                target_addr_count = target.addresses.len(),
                "upserted direct target hints"
            );
        }

        let mut helper_hints: std::collections::HashMap<ant_quic::PeerId, HelperHintEntry> =
            std::collections::HashMap::new();

        if let Some(ref cache) = self.bootstrap_cache {
            for peer in cache.select_coordinators(6).await {
                merge_helper_hint(
                    &mut helper_hints,
                    peer.peer_id,
                    "bootstrap_cache:coordinator",
                    peer.preferred_addresses(),
                    true,
                    false,
                );
            }
            for peer in cache.select_relay_peers(6).await {
                merge_helper_hint(
                    &mut helper_hints,
                    peer.peer_id,
                    "bootstrap_cache:relay",
                    peer.preferred_addresses(),
                    false,
                    true,
                );
            }
        }

        if let Some(ref adapter) = self.gossip_cache_adapter {
            let mut adverts = adapter.get_all_adverts();
            adverts.sort_by_key(|a| std::cmp::Reverse(a.score));
            for advert in adverts.into_iter().take(12) {
                let advert_peer_id = ant_quic::PeerId(*advert.peer.as_bytes());
                if advert_peer_id == target_peer_id {
                    continue;
                }
                merge_helper_hint(
                    &mut helper_hints,
                    advert_peer_id,
                    "gossip_cache_advert",
                    advert
                        .addr_hints
                        .into_iter()
                        .map(|hint| hint.addr)
                        .filter(|addr| is_publicly_advertisable(*addr)),
                    advert.roles.coordinator || advert.roles.rendezvous,
                    advert.roles.relay,
                );
            }
        }

        let discovered: Vec<DiscoveredMachine> = {
            let cache = self.machine_discovery_cache.read().await;
            cache.values().cloned().collect()
        };
        for candidate in discovered {
            if candidate.machine_id == target.machine_id || candidate.machine_id.0 == [0u8; 32] {
                continue;
            }
            merge_helper_hint(
                &mut helper_hints,
                ant_quic::PeerId(candidate.machine_id.0),
                "machine_discovery_cache",
                candidate.addresses.iter().copied(),
                candidate.is_coordinator == Some(true),
                candidate.is_relay == Some(true),
            );
        }

        let helper_candidate_count = helper_hints.len();
        let helper_addr_total: usize = helper_hints.values().map(|entry| entry.addrs.len()).sum();
        tracing::info!(
            target: "x0x::connect",
            stage = "seed_target_hints",
            %target_agent_prefix,
            %target_machine_prefix,
            target_addr_count = target.addresses.len(),
            helper_candidate_count,
            helper_addr_total,
            "prepared helper hints for peer-authenticated dial"
        );

        for (peer_id, entry) in &helper_hints {
            tracing::debug!(
                target: "x0x::connect",
                stage = "seed_target_hints",
                helper_peer_prefix = %network::hex_prefix(&peer_id.0, 4),
                helper_addr_count = entry.addrs.len(),
                supports_coordination = entry.caps.supports_coordination,
                supports_relay = entry.caps.supports_relay,
                sources = %entry.sources.iter().copied().collect::<Vec<_>>().join(","),
                "helper candidate discovered"
            );
        }

        for (peer_id, entry) in helper_hints {
            let HelperHintEntry {
                mut addrs,
                caps,
                sources,
            } = entry;
            addrs.retain(|addr| !target.addresses.contains(addr));
            if addrs.is_empty() && !caps.supports_coordination && !caps.supports_relay {
                tracing::debug!(
                    target: "x0x::connect",
                    stage = "seed_target_hints",
                    helper_peer_prefix = %network::hex_prefix(&peer_id.0, 4),
                    sources = %sources.iter().copied().collect::<Vec<_>>().join(","),
                    "skipping helper with no remaining addresses or assist capability"
                );
                continue;
            }
            tracing::debug!(
                target: "x0x::connect",
                stage = "seed_target_hints",
                helper_peer_prefix = %network::hex_prefix(&peer_id.0, 4),
                helper_addr_count = addrs.len(),
                supports_coordination = caps.supports_coordination,
                supports_relay = caps.supports_relay,
                sources = %sources.iter().copied().collect::<Vec<_>>().join(","),
                "upserting helper peer hints"
            );
            network
                .upsert_peer_hints(peer_id, addrs, Some(caps))
                .await
                .map_err(|e| {
                    error::IdentityError::Storage(std::io::Error::other(format!(
                        "failed to upsert helper peer hints: {e}"
                    )))
                })?;
        }

        Ok(())
    }

    /// Attempt to connect to an agent by its identity.
    ///
    /// Looks up the agent in the discovery cache, then tries to establish
    /// a QUIC connection using the best available strategy:
    ///
    /// 1. **Direct** — if the agent reports `can_receive_direct: true` or
    ///    has a traversable NAT type, try each known address in order.
    /// 2. **Coordinated** — if direct fails or the agent reports a symmetric
    ///    NAT, the outcome is `Coordinated` if any address was reachable via
    ///    the network layer's NAT traversal.
    /// 3. **Unreachable** — no address succeeded.
    /// 4. **NotFound** — the agent is not in the discovery cache.
    ///
    /// # Errors
    ///
    /// Returns an error only for internal failures (e.g. network not started).
    /// Connectivity failures are reported as `ConnectOutcome::Unreachable`.
    pub async fn connect_to_agent(
        &self,
        agent_id: &identity::AgentId,
    ) -> error::Result<connectivity::ConnectOutcome> {
        let call_start = std::time::Instant::now();
        let agent_prefix = network::hex_prefix(&agent_id.0, 4);
        tracing::debug!(
            target: "x0x::connect",
            stage = "connect_to_agent",
            %agent_prefix,
            "begin"
        );
        // 1. Look up in discovery cache
        let discovered = {
            let cache = self.identity_discovery_cache.read().await;
            cache.get(agent_id).cloned()
        };

        let agent = match discovered {
            Some(a) => a,
            None => {
                tracing::info!(
                    target: "x0x::connect",
                    stage = "connect_to_agent",
                    %agent_prefix,
                    outcome = "not_found",
                    dur_ms = call_start.elapsed().as_millis() as u64,
                    "agent not in discovery cache"
                );
                return Ok(connectivity::ConnectOutcome::NotFound);
            }
        };

        // #195 item 5: consult the revocation set inline so a known-revoked-but-
        // not-yet-evicted agent can't be the target of an outbound connect —
        // closes the race between a revocation arriving and the eviction loop
        // purging the discovery cache. Pairs with #191 item 5.
        {
            let revoked = self.revocation_set.read().await;
            if revoked.is_agent_revoked(agent_id) || revoked.is_machine_revoked(&agent.machine_id) {
                tracing::info!(
                    target: "x0x::connect",
                    stage = "connect_to_agent",
                    %agent_prefix,
                    outcome = "revoked",
                    dur_ms = call_start.elapsed().as_millis() as u64,
                    "connect target is revoked — refusing before any dial"
                );
                return Ok(connectivity::ConnectOutcome::NotFound);
            }
        }

        let info = connectivity::ReachabilityInfo::from_discovered(&agent);
        let v4_addrs = info.addresses.iter().filter(|a| a.is_ipv4()).count();
        let v6_addrs = info.addresses.len() - v4_addrs;
        tracing::info!(
            target: "x0x::connect",
            stage = "connect_to_agent",
            %agent_prefix,
            machine_prefix = %network::hex_prefix(&agent.machine_id.0, 4),
            addr_total = info.addresses.len(),
            v4_addrs,
            v6_addrs,
            can_receive_direct = ?info.can_receive_direct,
            should_attempt_direct = info.should_attempt_direct(),
            needs_coordination = info.needs_coordination(),
            "reachability classified"
        );

        let Some(ref network) = self.network else {
            tracing::warn!(
                target: "x0x::connect",
                stage = "connect_to_agent",
                agent_prefix = %crate::logging::LogHexId::agent(&agent_prefix),
                outcome = "unreachable_no_network",
                "network layer not initialised"
            );
            return Ok(connectivity::ConnectOutcome::Unreachable);
        };

        // 2. If already connected via gossip, reuse that connection.
        //    This check MUST come before the empty-address bail-out because
        //    LAN/private agents may have no publicly-routable addresses in
        //    their announcement but are still reachable via the existing
        //    gossip QUIC connection.
        let connected_machine_id = if agent.machine_id.0 != [0u8; 32]
            && network
                .is_connected(&ant_quic::PeerId(agent.machine_id.0))
                .await
        {
            Some(agent.machine_id)
        } else {
            match self.direct_messaging.get_machine_id(agent_id).await {
                Some(machine_id) if network.is_connected(&ant_quic::PeerId(machine_id.0)).await => {
                    Some(machine_id)
                }
                _ => None,
            }
        };
        if let Some(machine_id) = connected_machine_id {
            if machine_id != agent.machine_id {
                let mut cache = self.identity_discovery_cache.write().await;
                if let Some(entry) = cache.get_mut(agent_id) {
                    entry.machine_id = machine_id;
                }
            }
            self.direct_messaging
                .mark_connected(agent.agent_id, machine_id)
                .await;
            let dur_ms = call_start.elapsed().as_millis() as u64;
            return if let Some(addr) = info.addresses.first() {
                let family = if addr.is_ipv4() { "v4" } else { "v6" };
                tracing::info!(
                    target: "x0x::connect",
                    stage = "connect_to_agent",
                    %agent_prefix,
                    strategy = "already_connected",
                    outcome = "direct",
                    selected_addr = %addr,
                    family,
                    dur_ms,
                    "reusing existing connection"
                );
                Ok(connectivity::ConnectOutcome::Direct(*addr))
            } else {
                tracing::info!(
                    target: "x0x::connect",
                    stage = "connect_to_agent",
                    %agent_prefix,
                    strategy = "already_connected",
                    outcome = "already_connected",
                    dur_ms,
                    "reusing existing connection without known addr"
                );
                Ok(connectivity::ConnectOutcome::AlreadyConnected)
            };
        }

        if info.addresses.is_empty() {
            tracing::info!(
                target: "x0x::connect",
                stage = "connect_to_agent",
                %agent_prefix,
                outcome = "unreachable",
                reason = "no_addresses",
                dur_ms = call_start.elapsed().as_millis() as u64,
                "no known addresses for agent"
            );
            return Ok(connectivity::ConnectOutcome::Unreachable);
        }

        let dial_timeout = std::time::Duration::from_secs(8);
        let local_probe_timeout = std::time::Duration::from_secs(3);
        let direct_probe_addrs = local_direct_probe_addrs(&info.addresses);

        // Agent cards minted for a local dogfood run often contain both
        // reachable LAN IPv4 hints and globally-scoped IPv6/Tailscale hints
        // that may be stale or firewalled. Probe local IPv4 first so a bad
        // multi-address peer dial cannot consume the full API timeout before
        // the reachable LAN path is attempted.
        let peer_id_hint =
            (agent.machine_id.0 != [0u8; 32]).then_some(ant_quic::PeerId(agent.machine_id.0));
        for addr in &direct_probe_addrs {
            if let Some(peer_id_hint) = peer_id_hint {
                match tokio::time::timeout(
                    local_probe_timeout,
                    network.connect_peer_with_addrs(peer_id_hint, vec![*addr]),
                )
                .await
                {
                    Ok(Ok((selected_addr, connected_peer_id)))
                        if connected_peer_id == peer_id_hint =>
                    {
                        let real_machine_id = identity::MachineId(connected_peer_id.0);
                        if let Some(ref bc) = self.bootstrap_cache {
                            bc.add_from_connection(connected_peer_id, vec![selected_addr], None)
                                .await;
                        }
                        {
                            let mut cache = self.identity_discovery_cache.write().await;
                            if let Some(entry) = cache.get_mut(agent_id) {
                                entry.machine_id = real_machine_id;
                            }
                        }
                        self.direct_messaging
                            .mark_connected(agent.agent_id, real_machine_id)
                            .await;
                        tracing::info!(
                            target: "x0x::connect",
                            stage = "connect_to_agent",
                            %agent_prefix,
                            strategy = "local_direct_first",
                            outcome = "direct",
                            selected_addr = %selected_addr,
                            family = "v4",
                            dur_ms = call_start.elapsed().as_millis() as u64,
                            "local peer-authenticated dial succeeded"
                        );
                        return Ok(connectivity::ConnectOutcome::Direct(selected_addr));
                    }
                    Ok(Ok((selected_addr, connected_peer_id))) => {
                        tracing::warn!(
                            target: "x0x::connect",
                            stage = "connect_to_agent",
                            agent_prefix = %crate::logging::LogHexId::agent(&agent_prefix),
                            strategy = "local_direct_first",
                            requested_addr = %crate::logging::LogHexId::addr(&addr.to_string()),
                            selected_addr = %crate::logging::LogHexId::addr(&selected_addr.to_string()),
                            connected_machine_prefix = %crate::logging::LogHexId::new("machine", &network::hex_prefix(&connected_peer_id.0, 4)),
                            "local peer-authenticated dial reached unexpected peer"
                        );
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(
                            target: "x0x::connect",
                            %agent_prefix,
                            strategy = "local_direct_first",
                            %addr,
                            error = %e,
                            "local peer-authenticated dial failed; trying verified raw-address fallback"
                        );
                    }
                    Err(_) => {
                        tracing::debug!(
                            target: "x0x::connect",
                            %agent_prefix,
                            strategy = "local_direct_first",
                            %addr,
                            timeout_s = local_probe_timeout.as_secs(),
                            "local peer-authenticated dial timed out; trying verified raw-address fallback"
                        );
                    }
                }

                match tokio::time::timeout(local_probe_timeout, network.connect_addr(*addr)).await {
                    Ok(Ok(connected_peer_id)) if connected_peer_id == peer_id_hint => {
                        let real_machine_id = identity::MachineId(connected_peer_id.0);
                        if let Some(ref bc) = self.bootstrap_cache {
                            bc.add_from_connection(connected_peer_id, vec![*addr], None)
                                .await;
                        }
                        {
                            let mut cache = self.identity_discovery_cache.write().await;
                            if let Some(entry) = cache.get_mut(agent_id) {
                                entry.machine_id = real_machine_id;
                            }
                        }
                        self.direct_messaging
                            .mark_connected(agent.agent_id, real_machine_id)
                            .await;
                        tracing::info!(
                            target: "x0x::connect",
                            stage = "connect_to_agent",
                            %agent_prefix,
                            strategy = "local_direct_raw_fallback",
                            outcome = "direct",
                            selected_addr = %addr,
                            family = "v4",
                            dur_ms = call_start.elapsed().as_millis() as u64,
                            "verified local raw-address fallback succeeded"
                        );
                        return Ok(connectivity::ConnectOutcome::Direct(*addr));
                    }
                    Ok(Ok(connected_peer_id)) => {
                        tracing::warn!(
                            target: "x0x::connect",
                            stage = "connect_to_agent",
                            agent_prefix = %crate::logging::LogHexId::agent(&agent_prefix),
                            strategy = "local_direct_raw_fallback",
                            addr = %crate::logging::LogHexId::addr(&addr.to_string()),
                            connected_machine_prefix = %crate::logging::LogHexId::new("machine", &network::hex_prefix(&connected_peer_id.0, 4)),
                            "verified local raw-address fallback reached unexpected peer"
                        );
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(
                            target: "x0x::connect",
                            %agent_prefix,
                            strategy = "local_direct_raw_fallback",
                            %addr,
                            error = %e,
                            "verified local raw-address fallback failed"
                        );
                    }
                    Err(_) => {
                        tracing::debug!(
                            target: "x0x::connect",
                            %agent_prefix,
                            strategy = "local_direct_raw_fallback",
                            %addr,
                            timeout_s = local_probe_timeout.as_secs(),
                            "verified local raw-address fallback timed out"
                        );
                    }
                }
            } else {
                match tokio::time::timeout(local_probe_timeout, network.connect_addr(*addr)).await {
                    Ok(Ok(connected_peer_id)) => {
                        let real_machine_id = identity::MachineId(connected_peer_id.0);
                        if let Some(ref bc) = self.bootstrap_cache {
                            bc.add_from_connection(connected_peer_id, vec![*addr], None)
                                .await;
                        }
                        {
                            let mut cache = self.identity_discovery_cache.write().await;
                            if let Some(entry) = cache.get_mut(agent_id) {
                                entry.machine_id = real_machine_id;
                            }
                        }
                        self.direct_messaging
                            .mark_connected(agent.agent_id, real_machine_id)
                            .await;
                        tracing::info!(
                            target: "x0x::connect",
                            stage = "connect_to_agent",
                            %agent_prefix,
                            strategy = "local_direct_first",
                            outcome = "direct",
                            selected_addr = %addr,
                            family = "v4",
                            dur_ms = call_start.elapsed().as_millis() as u64,
                            "local direct dial succeeded"
                        );
                        return Ok(connectivity::ConnectOutcome::Direct(*addr));
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(
                            target: "x0x::connect",
                            %agent_prefix,
                            strategy = "local_direct_first",
                            %addr,
                            error = %e,
                            "local direct dial failed"
                        );
                    }
                    Err(_) => {
                        tracing::debug!(
                            target: "x0x::connect",
                            %agent_prefix,
                            strategy = "local_direct_first",
                            %addr,
                            timeout_s = local_probe_timeout.as_secs(),
                            "local direct dial timed out"
                        );
                    }
                }
            }
        }

        // 3. If we know the peer's machine ID, prefer a peer-authenticated dial
        //    with explicit address hints first. This is more reliable for agent
        //    cards and other out-of-band discoveries than a raw address dial.
        if agent.machine_id.0 != [0u8; 32] {
            let peer_id_hint = ant_quic::PeerId(agent.machine_id.0);
            self.seed_transport_peer_hints_for_target(network, &agent)
                .await
                .map_err(|e| {
                    error::IdentityError::Storage(std::io::Error::other(format!(
                        "failed to seed transport peer hints: {e}"
                    )))
                })?;

            match tokio::time::timeout(
                dial_timeout,
                network.connect_peer_with_addrs(peer_id_hint, info.addresses.clone()),
            )
            .await
            {
                Ok(Ok((addr, verified_peer_id))) => {
                    let verified_machine_id = identity::MachineId(verified_peer_id.0);
                    if let Some(ref bc) = self.bootstrap_cache {
                        bc.add_from_connection(verified_peer_id, vec![addr], None)
                            .await;
                        bc.record_success(&verified_peer_id, 0).await;
                    }
                    {
                        let mut cache = self.identity_discovery_cache.write().await;
                        if let Some(entry) = cache.get_mut(agent_id) {
                            entry.machine_id = verified_machine_id;
                        }
                    }
                    self.direct_messaging
                        .mark_connected(agent.agent_id, verified_machine_id)
                        .await;
                    let family = if addr.is_ipv4() { "v4" } else { "v6" };
                    tracing::info!(
                        target: "x0x::connect",
                        stage = "connect_to_agent",
                        %agent_prefix,
                        strategy = "hinted_peer",
                        outcome = "coordinated",
                        selected_addr = %addr,
                        family,
                        dur_ms = call_start.elapsed().as_millis() as u64,
                        "hinted peer dial succeeded"
                    );
                    return Ok(connectivity::ConnectOutcome::Coordinated(addr));
                }
                Ok(Err(e)) => {
                    tracing::debug!(
                        target: "x0x::connect",
                        %agent_prefix,
                        strategy = "hinted_peer",
                        error = %e,
                        "hinted peer dial failed"
                    );
                }
                Err(_) => {
                    tracing::debug!(
                        target: "x0x::connect",
                        %agent_prefix,
                        strategy = "hinted_peer",
                        timeout_s = dial_timeout.as_secs(),
                        "hinted peer dial timed out"
                    );
                }
            }
        }

        // 4. Try direct connection whenever the peer is not explicitly known
        //    to require coordination. Unknown reachability still deserves a
        //    direct probe, especially for the first nodes in a new network.
        if info.should_attempt_direct() {
            for addr in &info.addresses {
                if direct_probe_addrs.contains(addr) {
                    continue;
                }
                match tokio::time::timeout(dial_timeout, network.connect_addr(*addr)).await {
                    Ok(Ok(connected_peer_id)) => {
                        // Use the real PeerId from the QUIC handshake (may differ
                        // from a zeroed placeholder in the discovery cache).
                        let real_machine_id = identity::MachineId(connected_peer_id.0);
                        // Enrich bootstrap cache with this successful address
                        if let Some(ref bc) = self.bootstrap_cache {
                            bc.add_from_connection(connected_peer_id, vec![*addr], None)
                                .await;
                        }
                        // Update discovery cache with real machine_id
                        {
                            let mut cache = self.identity_discovery_cache.write().await;
                            if let Some(entry) = cache.get_mut(agent_id) {
                                entry.machine_id = real_machine_id;
                            }
                        }
                        // Register agent mapping for direct messaging
                        self.direct_messaging
                            .mark_connected(agent.agent_id, real_machine_id)
                            .await;
                        let family = if addr.is_ipv4() { "v4" } else { "v6" };
                        tracing::info!(
                            target: "x0x::connect",
                            stage = "connect_to_agent",
                            %agent_prefix,
                            strategy = "direct_per_addr",
                            outcome = "direct",
                            selected_addr = %addr,
                            family,
                            dur_ms = call_start.elapsed().as_millis() as u64,
                            "direct dial succeeded"
                        );
                        return Ok(connectivity::ConnectOutcome::Direct(*addr));
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(
                            target: "x0x::connect",
                            %agent_prefix,
                            strategy = "direct_per_addr",
                            %addr,
                            error = %e,
                            "direct dial failed"
                        );
                    }
                    Err(_) => {
                        tracing::debug!(
                            target: "x0x::connect",
                            %agent_prefix,
                            strategy = "direct_per_addr",
                            %addr,
                            timeout_s = dial_timeout.as_secs(),
                            "direct dial timed out"
                        );
                    }
                }
            }
        }

        // 5. If direct failed and coordination may help, use peer-ID dialing
        //    with explicit address hints. This lets ant-quic combine the
        //    authenticated peer ID with known addresses from x0x discovery /
        //    imported cards, unlocking the full direct → hole-punch → relay path.
        if info.needs_coordination() || !info.should_attempt_direct() {
            // Prefer coordinators the target has explicitly named in its
            // announcement (`reachable_via`). Seed transport hints for each
            // so ant-quic picks whichever is already connected (or can reach
            // one) as the coordinator peer for NAT punch-timing.
            for coord in &info.reachable_via {
                if let Some(coord_machine) = self
                    .machine_discovery_cache
                    .read()
                    .await
                    .get(coord)
                    .cloned()
                {
                    let coord_peer = ant_quic::PeerId(coord_machine.machine_id.0);
                    let coord_addrs = coord_machine.addresses.clone();
                    if !coord_addrs.is_empty() {
                        if let Err(e) = network
                            .upsert_peer_hints(coord_peer, coord_addrs, None)
                            .await
                        {
                            tracing::debug!(
                                target: "x0x::connect",
                                %agent_prefix,
                                coord_prefix = %network::hex_prefix(&coord.0, 4),
                                error = %e,
                                "failed to seed coordinator hints from reachable_via"
                            );
                        }
                    }
                }
            }

            // Use the machine_id from discovery cache as the peer_id hint.
            // NOTE: This may be a zeroed placeholder if the peer was discovered via
            // gossip and hasn't been verified via QUIC handshake yet.
            let peer_id_hint = ant_quic::PeerId(agent.machine_id.0);
            let hint_was_zeroed = agent.machine_id.0 == [0u8; 32];
            self.seed_transport_peer_hints_for_target(network, &agent)
                .await
                .map_err(|e| {
                    error::IdentityError::Storage(std::io::Error::other(format!(
                        "failed to seed transport peer hints: {e}"
                    )))
                })?;
            let coordinated_result = tokio::time::timeout(
                dial_timeout,
                network.connect_peer_with_addrs(peer_id_hint, info.addresses.clone()),
            )
            .await;
            match coordinated_result {
                Ok(Ok((addr, verified_peer_id))) => {
                    let verified_machine_id = identity::MachineId(verified_peer_id.0);

                    // Only update caches if the original hint was not zeroed.
                    // When the hint was zeroed, we connected to *some* peer at that address
                    // but have no way to verify they are the agent we intended. Writing
                    // an unverified peer_id into the caches could corrupt the bootstrap cache
                    // with the wrong peer's identity.
                    if !hint_was_zeroed {
                        if let Some(ref bc) = self.bootstrap_cache {
                            bc.add_from_connection(verified_peer_id, vec![addr], None)
                                .await;
                            bc.record_success(&verified_peer_id, 0).await;
                        }
                        {
                            let mut cache = self.identity_discovery_cache.write().await;
                            if let Some(entry) = cache.get_mut(agent_id) {
                                entry.machine_id = verified_machine_id;
                            }
                        }
                    }

                    // Only register for direct messaging and update caches when the hint
                    // was non-zero. When the hint was zeroed, we connected to *some*
                    // peer at that address but have no cryptographic way to verify they
                    // are the agent we intended. Binding an unverified peer_id to an
                    // agent_id could corrupt the direct-messaging registry with the
                    // wrong peer's identity.
                    if !hint_was_zeroed {
                        self.direct_messaging
                            .mark_connected(agent.agent_id, verified_machine_id)
                            .await;
                    }
                    let family = if addr.is_ipv4() { "v4" } else { "v6" };
                    tracing::info!(
                        target: "x0x::connect",
                        stage = "connect_to_agent",
                        %agent_prefix,
                        strategy = "coordinated_fallback",
                        outcome = "coordinated",
                        selected_addr = %addr,
                        family,
                        hint_was_zeroed,
                        dur_ms = call_start.elapsed().as_millis() as u64,
                        "coordinated dial succeeded"
                    );
                    return Ok(connectivity::ConnectOutcome::Coordinated(addr));
                }
                Ok(Err(e)) => {
                    tracing::debug!(
                        target: "x0x::connect",
                        %agent_prefix,
                        strategy = "coordinated_fallback",
                        error = %e,
                        "coordinated dial failed"
                    );
                }
                Err(_) => {
                    tracing::debug!(
                        target: "x0x::connect",
                        %agent_prefix,
                        strategy = "coordinated_fallback",
                        timeout_s = dial_timeout.as_secs(),
                        "coordinated dial timed out"
                    );
                }
            }
        }

        tracing::warn!(
            target: "x0x::connect",
            stage = "connect_to_agent",
            agent_prefix = %crate::logging::LogHexId::agent(&agent_prefix),
            outcome = "unreachable",
            reason = "all_strategies_exhausted",
            dur_ms = call_start.elapsed().as_millis() as u64,
            v4_addrs,
            v6_addrs,
            "all connection strategies exhausted"
        );
        Ok(connectivity::ConnectOutcome::Unreachable)
    }

    /// Attempt to connect to a machine by its transport identity.
    ///
    /// This is the machine-centric dial path: `machine_id` is resolved to
    /// IPv4/IPv6 endpoint hints, then ant-quic performs a peer-authenticated
    /// dial that can use direct connection, coordinated hole-punching, or relay
    /// support according to the transport cache.
    ///
    /// # Errors
    ///
    /// Returns an error only for internal failures. Connectivity failures are
    /// reported as [`connectivity::ConnectOutcome::Unreachable`].
    pub async fn connect_to_machine(
        &self,
        machine_id: &identity::MachineId,
    ) -> error::Result<connectivity::ConnectOutcome> {
        let call_start = std::time::Instant::now();
        let machine_prefix = network::hex_prefix(&machine_id.0, 4);
        tracing::debug!(
            target: "x0x::connect",
            stage = "connect_to_machine",
            %machine_prefix,
            "begin"
        );

        let machine = {
            let cache = self.machine_discovery_cache.read().await;
            cache.get(machine_id).cloned()
        };
        let Some(machine) = machine else {
            tracing::info!(
                target: "x0x::connect",
                stage = "connect_to_machine",
                %machine_prefix,
                outcome = "not_found",
                dur_ms = call_start.elapsed().as_millis() as u64,
                "machine not in discovery cache"
            );
            return Ok(connectivity::ConnectOutcome::NotFound);
        };

        let Some(ref network) = self.network else {
            tracing::warn!(
                target: "x0x::connect",
                stage = "connect_to_machine",
                machine_prefix = %crate::logging::LogHexId::new("machine", &machine_prefix),
                outcome = "unreachable_no_network",
                "network layer not initialised"
            );
            return Ok(connectivity::ConnectOutcome::Unreachable);
        };

        let peer_id = ant_quic::PeerId(machine.machine_id.0);
        if network.is_connected(&peer_id).await {
            for agent_id in &machine.agent_ids {
                self.direct_messaging
                    .mark_connected(*agent_id, machine.machine_id)
                    .await;
            }
            return if let Some(addr) = machine.addresses.first() {
                Ok(connectivity::ConnectOutcome::Direct(*addr))
            } else {
                Ok(connectivity::ConnectOutcome::AlreadyConnected)
            };
        }

        let info = connectivity::ReachabilityInfo::from_discovered_machine(&machine);
        let v4_addrs = info.addresses.iter().filter(|a| a.is_ipv4()).count();
        let v6_addrs = info.addresses.len() - v4_addrs;
        tracing::info!(
            target: "x0x::connect",
            stage = "connect_to_machine",
            %machine_prefix,
            addr_total = info.addresses.len(),
            v4_addrs,
            v6_addrs,
            can_receive_direct = ?info.can_receive_direct,
            should_attempt_direct = info.should_attempt_direct(),
            needs_coordination = info.needs_coordination(),
            "machine reachability classified"
        );

        if info.addresses.is_empty() {
            return Ok(connectivity::ConnectOutcome::Unreachable);
        }

        let dial_timeout = std::time::Duration::from_secs(8);
        let local_probe_timeout = std::time::Duration::from_secs(3);
        let direct_probe_addrs = local_direct_probe_addrs(&info.addresses);

        for addr in &direct_probe_addrs {
            match tokio::time::timeout(
                local_probe_timeout,
                network.connect_peer_with_addrs(peer_id, vec![*addr]),
            )
            .await
            {
                Ok(Ok((selected_addr, connected_peer_id))) if connected_peer_id == peer_id => {
                    if let Some(ref bc) = self.bootstrap_cache {
                        bc.add_from_connection(connected_peer_id, vec![selected_addr], None)
                            .await;
                    }
                    for agent_id in &machine.agent_ids {
                        self.direct_messaging
                            .mark_connected(*agent_id, machine.machine_id)
                            .await;
                    }
                    tracing::info!(
                        target: "x0x::connect",
                        stage = "connect_to_machine",
                        %machine_prefix,
                        strategy = "local_direct_first",
                        outcome = "direct",
                        selected_addr = %selected_addr,
                        dur_ms = call_start.elapsed().as_millis() as u64,
                        "machine local direct dial succeeded"
                    );
                    return Ok(connectivity::ConnectOutcome::Direct(selected_addr));
                }
                Ok(Ok((selected_addr, connected_peer_id))) => {
                    tracing::warn!(
                        target: "x0x::connect",
                        stage = "connect_to_machine",
                        machine_prefix = %crate::logging::LogHexId::new("machine", &machine_prefix),
                        requested_addr = %crate::logging::LogHexId::addr(&addr.to_string()),
                        selected_addr = %crate::logging::LogHexId::addr(&selected_addr.to_string()),
                        connected_machine_prefix = %crate::logging::LogHexId::new("machine", &network::hex_prefix(&connected_peer_id.0, 4)),
                        "machine local direct dial reached unexpected peer"
                    );
                }
                Ok(Err(e)) => {
                    tracing::debug!(
                        target: "x0x::connect",
                        stage = "connect_to_machine",
                        %machine_prefix,
                        strategy = "local_direct_first",
                        %addr,
                        error = %e,
                        "machine local direct dial failed"
                    );
                }
                Err(_) => {
                    tracing::debug!(
                        target: "x0x::connect",
                        stage = "connect_to_machine",
                        %machine_prefix,
                        strategy = "local_direct_first",
                        %addr,
                        timeout_s = local_probe_timeout.as_secs(),
                        "machine local direct dial timed out"
                    );
                }
            }

            match tokio::time::timeout(local_probe_timeout, network.connect_addr(*addr)).await {
                Ok(Ok(connected_peer_id)) if connected_peer_id == peer_id => {
                    if let Some(ref bc) = self.bootstrap_cache {
                        bc.add_from_connection(connected_peer_id, vec![*addr], None)
                            .await;
                    }
                    for agent_id in &machine.agent_ids {
                        self.direct_messaging
                            .mark_connected(*agent_id, machine.machine_id)
                            .await;
                    }
                    tracing::info!(
                        target: "x0x::connect",
                        stage = "connect_to_machine",
                        %machine_prefix,
                        strategy = "local_direct_raw_fallback",
                        outcome = "direct",
                        selected_addr = %addr,
                        dur_ms = call_start.elapsed().as_millis() as u64,
                        "verified machine local raw-address fallback succeeded"
                    );
                    return Ok(connectivity::ConnectOutcome::Direct(*addr));
                }
                Ok(Ok(connected_peer_id)) => {
                    tracing::warn!(
                        target: "x0x::connect",
                        stage = "connect_to_machine",
                        machine_prefix = %crate::logging::LogHexId::new("machine", &machine_prefix),
                        strategy = "local_direct_raw_fallback",
                        addr = %crate::logging::LogHexId::addr(&addr.to_string()),
                        connected_machine_prefix = %crate::logging::LogHexId::new("machine", &network::hex_prefix(&connected_peer_id.0, 4)),
                        "verified machine local raw-address fallback reached unexpected peer"
                    );
                }
                Ok(Err(e)) => {
                    tracing::debug!(
                        target: "x0x::connect",
                        stage = "connect_to_machine",
                        %machine_prefix,
                        strategy = "local_direct_raw_fallback",
                        %addr,
                        error = %e,
                        "verified machine local raw-address fallback failed"
                    );
                }
                Err(_) => {
                    tracing::debug!(
                        target: "x0x::connect",
                        stage = "connect_to_machine",
                        %machine_prefix,
                        strategy = "local_direct_raw_fallback",
                        %addr,
                        timeout_s = local_probe_timeout.as_secs(),
                        "verified machine local raw-address fallback timed out"
                    );
                }
            }
        }

        network
            .upsert_peer_hints(peer_id, info.addresses.clone(), None)
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "failed to upsert machine peer hints: {e}"
                )))
            })?;

        match tokio::time::timeout(
            dial_timeout,
            network.connect_peer_with_addrs(peer_id, info.addresses.clone()),
        )
        .await
        {
            Ok(Ok((addr, verified_peer_id))) if verified_peer_id == peer_id => {
                if let Some(ref bc) = self.bootstrap_cache {
                    bc.add_from_connection(verified_peer_id, vec![addr], None)
                        .await;
                    bc.record_success(&verified_peer_id, 0).await;
                }
                for agent_id in &machine.agent_ids {
                    self.direct_messaging
                        .mark_connected(*agent_id, machine.machine_id)
                        .await;
                }
                tracing::info!(
                    target: "x0x::connect",
                    stage = "connect_to_machine",
                    %machine_prefix,
                    strategy = "hinted_peer",
                    outcome = "coordinated",
                    selected_addr = %addr,
                    dur_ms = call_start.elapsed().as_millis() as u64,
                    "machine peer-authenticated dial succeeded"
                );
                return Ok(connectivity::ConnectOutcome::Coordinated(addr));
            }
            Ok(Ok((addr, verified_peer_id))) => {
                tracing::warn!(
                    target: "x0x::connect",
                    stage = "connect_to_machine",
                    machine_prefix = %crate::logging::LogHexId::new("machine", &machine_prefix),
                    selected_addr = %crate::logging::LogHexId::addr(&addr.to_string()),
                    verified_machine_prefix = %crate::logging::LogHexId::new("machine", &network::hex_prefix(&verified_peer_id.0, 4)),
                    "machine dial reached unexpected peer"
                );
            }
            Ok(Err(e)) => {
                tracing::debug!(
                    target: "x0x::connect",
                    stage = "connect_to_machine",
                    %machine_prefix,
                    error = %e,
                    "machine peer-authenticated dial failed"
                );
            }
            Err(_) => {
                tracing::debug!(
                    target: "x0x::connect",
                    stage = "connect_to_machine",
                    %machine_prefix,
                    timeout_s = dial_timeout.as_secs(),
                    "machine peer-authenticated dial timed out"
                );
            }
        }

        if info.should_attempt_direct() {
            for addr in &info.addresses {
                if direct_probe_addrs.contains(addr) {
                    continue;
                }
                match tokio::time::timeout(dial_timeout, network.connect_addr(*addr)).await {
                    Ok(Ok(connected_peer_id)) if connected_peer_id == peer_id => {
                        if let Some(ref bc) = self.bootstrap_cache {
                            bc.add_from_connection(connected_peer_id, vec![*addr], None)
                                .await;
                        }
                        for agent_id in &machine.agent_ids {
                            self.direct_messaging
                                .mark_connected(*agent_id, machine.machine_id)
                                .await;
                        }
                        tracing::info!(
                            target: "x0x::connect",
                            stage = "connect_to_machine",
                            %machine_prefix,
                            strategy = "direct_per_addr",
                            outcome = "direct",
                            selected_addr = %addr,
                            dur_ms = call_start.elapsed().as_millis() as u64,
                            "machine direct dial succeeded"
                        );
                        return Ok(connectivity::ConnectOutcome::Direct(*addr));
                    }
                    Ok(Ok(connected_peer_id)) => {
                        tracing::warn!(
                            target: "x0x::connect",
                            stage = "connect_to_machine",
                            machine_prefix = %crate::logging::LogHexId::new("machine", &machine_prefix),
                            addr = %crate::logging::LogHexId::addr(&addr.to_string()),
                            connected_machine_prefix = %crate::logging::LogHexId::new("machine", &network::hex_prefix(&connected_peer_id.0, 4)),
                            "machine direct dial reached unexpected peer"
                        );
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(
                            target: "x0x::connect",
                            stage = "connect_to_machine",
                            %machine_prefix,
                            %addr,
                            error = %e,
                            "machine direct dial failed"
                        );
                    }
                    Err(_) => {
                        tracing::debug!(
                            target: "x0x::connect",
                            stage = "connect_to_machine",
                            %machine_prefix,
                            %addr,
                            timeout_s = dial_timeout.as_secs(),
                            "machine direct dial timed out"
                        );
                    }
                }
            }
        }

        tracing::warn!(
            target: "x0x::connect",
            stage = "connect_to_machine",
            machine_prefix = %crate::logging::LogHexId::new("machine", &machine_prefix),
            outcome = "unreachable",
            reason = "all_strategies_exhausted",
            dur_ms = call_start.elapsed().as_millis() as u64,
            v4_addrs,
            v6_addrs,
            "all machine connection strategies exhausted"
        );
        Ok(connectivity::ConnectOutcome::Unreachable)
    }

    /// Spawn a background task whose handle is tracked for deterministic
    /// teardown. Returns without spawning once the registry is `closed` (i.e.
    /// `shutdown()` has begun) — this is what closes the join_network race:
    /// a listener requested after shutdown started must never run.
    fn spawn_tracked<F>(&self, fut: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        // Lock held only to inspect `closed` and push the handle; no await
        // happens under it (Rule: keep the std::Mutex hold trivially short).
        let mut guard = match self.tracked_tasks.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.closed {
            return;
        }
        guard.handles.push(tokio::spawn(fut));
    }

    /// Begin shutdown WITHOUT tearing anything down yet: cancel the shutdown
    /// token and close the tracked-task registry. Idempotent and synchronous.
    ///
    /// This is the prefix of `shutdown()`, split out so an embedder/server can
    /// cancel BEFORE draining its own background tasks (notably a still-running
    /// `join_network`). Once this returns, every `start_*` helper refuses to
    /// start (they check `shutdown_token.is_cancelled()` under their handle
    /// lock) and `spawn_tracked` refuses to spawn — so a `join_network` that is
    /// still finishing cannot leak a heartbeat/reaper/presence/advert/inbox
    /// task past the subsequent `shutdown()`. `shutdown()` still cancels the
    /// token itself (idempotent), so calling `shutdown()` alone remains correct.
    pub fn begin_shutdown(&self) {
        self.shutdown_token.cancel();
        let mut guard = match self.tracked_tasks.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.closed = true;
    }

    /// Save the bootstrap cache and release resources.
    ///
    /// Call this before dropping the agent to ensure the peer cache is
    /// persisted to disk. The background maintenance task saves periodically,
    /// but this guarantees a final save.
    ///
    /// Shutdown ordering is deliberate: the cancellation token is cancelled and
    /// the listener tasks are stopped *before* the gossip runtime and the
    /// network node are torn down. The listeners call into the network (e.g.
    /// `is_connected`), so stopping them first avoids a Phase-2-style hang where
    /// a listener blocks on a transport that is concurrently shutting down.
    /// Idempotent: `cancel()` is idempotent, the registry drains empty on a
    /// second call, and the `stop_*` helpers use `Option::take`.
    pub async fn shutdown(&self) {
        // 1. Signal every token-aware loop to break. Inert until now, so this
        //    is the first thing that changes steady-state behavior.
        self.shutdown_token.cancel();

        // 2. Stop the simple Option<JoinHandle> background tasks.
        self.stop_identity_heartbeat().await;
        self.stop_discovery_cache_reaper().await;

        // 3. Stop the DM inbox and the capability advert service (current gaps:
        //    neither was stopped by shutdown() before). Both abort their own
        //    spawned tasks.
        self.stop_dm_inbox().await;
        {
            let service = {
                let mut guard = self.capability_advert_service.lock().await;
                guard.take()
            };
            if let Some(service) = service {
                service.abort();
            }
        }

        // 4. Drain the tracked-task registry: mark closed (so any in-flight
        //    spawn_tracked is refused), take the handles, grace-await them all
        //    under a SINGLE bounded budget (not per-task — keeps shutdown
        //    prompt), then abort+await any straggler. A cancelled/aborted task
        //    yields Err(JoinError); that is expected, never unwrap it.
        let handles = {
            let mut guard = match self.tracked_tasks.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.closed = true;
            std::mem::take(&mut guard.handles)
        };
        if !handles.is_empty() {
            // Grace-await all tracked tasks under a SINGLE bounded budget (not
            // per-task — keeps shutdown prompt regardless of task count). On
            // timeout, abort the stragglers and await the aborts so none
            // outlives shutdown(). The select! keeps the JoinHandles owned by
            // the awaiting future so the post-abort join can still observe each
            // task's terminal JoinError (cancelled tasks → Err — never
            // unwrapped).
            let abort_handles: Vec<tokio::task::AbortHandle> =
                handles.iter().map(|h| h.abort_handle()).collect();
            let mut join = futures::future::join_all(handles);
            tokio::select! {
                _results = &mut join => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {
                    tracing::warn!(
                        "Agent background tasks did not stop within grace; aborting stragglers"
                    );
                    for handle in &abort_handles {
                        handle.abort();
                    }
                    let _results: Vec<Result<(), tokio::task::JoinError>> = join.await;
                }
            }
        }

        // Shut down presence beacons.
        if let Some(ref pw) = self.presence {
            pw.shutdown().await;
            tracing::info!("Presence system shut down");
        }

        if let Some(ref cache) = self.bootstrap_cache {
            if let Err(e) = cache.save().await {
                tracing::warn!("Failed to save bootstrap cache on shutdown: {e}");
            } else {
                tracing::info!("Bootstrap cache saved on shutdown");
            }
        }

        // Issue #110 Phase 2: tear down the gossip runtime and the QUIC node so
        // an in-process embedder gets the socket and all background tasks back
        // when `shutdown()` returns. The gossip runtime's dispatcher/peer-sync/
        // keepalive tasks hold the transport (and thus the ant-quic endpoint)
        // alive; the daemon binary survives only by process exit, but an
        // embedded host needs these released to re-`serve()` on the same port.
        if let Some(ref runtime) = self.gossip_runtime {
            if let Err(e) = runtime.shutdown().await {
                tracing::warn!("Gossip runtime shutdown error: {e}");
            } else {
                tracing::info!("Gossip runtime shut down");
            }
        }
        if let Some(ref network) = self.network {
            network.shutdown().await;
            tracing::info!("Network node shut down");
        }
    }

    async fn stop_identity_heartbeat(&self) {
        let handle = {
            let mut handle_guard = self.heartbeat_handle.lock().await;
            handle_guard.take()
        };

        if let Some(handle) = handle {
            handle.abort();
            match handle.await {
                Ok(()) => tracing::debug!("Identity heartbeat task stopped"),
                Err(e) if e.is_cancelled() => {
                    tracing::debug!("Identity heartbeat task aborted")
                }
                Err(e) => tracing::warn!("Identity heartbeat task failed during shutdown: {e}"),
            }
        }
    }

    async fn stop_discovery_cache_reaper(&self) {
        let handle = {
            let mut handle_guard = self.discovery_cache_reaper_handle.lock().await;
            handle_guard.take()
        };

        if let Some(handle) = handle {
            handle.abort();
            match handle.await {
                Ok(()) => tracing::debug!("Discovery cache reaper stopped"),
                Err(e) if e.is_cancelled() => {
                    tracing::debug!("Discovery cache reaper aborted")
                }
                Err(e) => tracing::warn!("Discovery cache reaper failed during shutdown: {e}"),
            }
        }
    }

    /// Background task body: periodically prunes the three discovery caches
    /// using the same TTL logic as the query paths (last_seen >= cutoff).
    /// This is the active counterpart to the previous read-only filtering,
    /// preventing unbounded accumulation on long-running daemons.
    async fn discovery_cache_reaper_loop(
        identity_cache: std::sync::Arc<
            tokio::sync::RwLock<std::collections::HashMap<identity::AgentId, DiscoveredAgent>>,
        >,
        machine_cache: std::sync::Arc<
            tokio::sync::RwLock<std::collections::HashMap<identity::MachineId, DiscoveredMachine>>,
        >,
        user_cache: std::sync::Arc<
            tokio::sync::RwLock<std::collections::HashMap<identity::UserId, DiscoveredUser>>,
        >,
        ttl_secs: u64,
        interval: std::time::Duration,
    ) {
        loop {
            tokio::time::sleep(interval).await;
            let cutoff = Self::unix_timestamp_secs().saturating_sub(ttl_secs);
            // Identity cache
            {
                let mut c = identity_cache.write().await;
                c.retain(|_, a| a.last_seen >= cutoff);
            }
            // Machine cache
            {
                let mut c = machine_cache.write().await;
                c.retain(|_, m| m.last_seen >= cutoff);
            }
            // User cache
            {
                let mut c = user_cache.write().await;
                c.retain(|_, u| u.last_seen >= cutoff);
            }
        }
    }

    async fn start_discovery_cache_reaper(&self) -> error::Result<()> {
        let mut guard = self.discovery_cache_reaper_handle.lock().await;
        // Shutdown race (issue #116): refuse to start once shutdown began.
        // Checked under the same lock stop_discovery_cache_reaper takes from.
        if self.shutdown_token.is_cancelled() {
            return Ok(());
        }
        if guard.is_some() {
            return Ok(());
        }

        let identity = std::sync::Arc::clone(&self.identity_discovery_cache);
        let machine = std::sync::Arc::clone(&self.machine_discovery_cache);
        let user = std::sync::Arc::clone(&self.user_discovery_cache);
        let ttl = self.identity_ttl_secs;
        let interval = std::time::Duration::from_secs(DISCOVERY_CACHE_REAPER_INTERVAL_SECS);

        let handle = tokio::spawn(Self::discovery_cache_reaper_loop(
            identity, machine, user, ttl, interval,
        ));
        *guard = Some(handle);
        Ok(())
    }

    // === Direct Messaging ===

    /// Send data directly to a connected agent.
    ///
    /// This bypasses gossip pub/sub for efficient point-to-point communication.
    /// The agent must be connected first via [`Self::connect_to_agent`].
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The target agent's identifier.
    /// * `payload` - The data to send.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Network is not initialized
    /// - Agent is not connected
    /// - Agent is not found in discovery cache
    /// - Send fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // First connect to the agent
    /// let outcome = agent.connect_to_agent(&target_agent_id).await?;
    ///
    /// // Then send data directly
    /// agent.send_direct(&target_agent_id, b"hello".to_vec()).await?;
    /// ```
    /// Send data directly to an agent — capability-aware dispatch.
    ///
    /// Looks up the recipient's `DmCapabilities` in the local
    /// [`dm_capability::CapabilityStore`]. If the recipient advertises
    /// `gossip_inbox=true` with a non-empty `kem_public_key`, the send
    /// goes via the gossip DM path (signed+encrypted envelope published
    /// to the recipient's inbox topic with an application-layer ACK).
    /// Otherwise, falls back to the legacy raw-QUIC stream.
    ///
    /// # Errors
    ///
    /// See [`dm::DmError`].
    ///
    /// Uses the default capability-aware policy. Call
    /// [`Self::send_direct_with_config`] to opt into the raw-QUIC fast path
    /// explicitly.
    pub async fn send_direct(
        &self,
        to: &identity::AgentId,
        payload: Vec<u8>,
    ) -> Result<dm::DmReceipt, dm::DmError> {
        self.send_direct_with_config(to, payload, dm::DmSendConfig::default())
            .await
    }

    async fn dm_peer_rtt_ms(&self, agent_id: &identity::AgentId) -> Option<u32> {
        let registry_machine_id = self.direct_messaging.get_machine_id(agent_id).await;
        let cached_machine_id = {
            let cache = self.identity_discovery_cache.read().await;
            cache
                .get(agent_id)
                .map(|entry| entry.machine_id)
                .filter(|machine_id| machine_id.0 != [0_u8; 32])
        };
        let machine_id = registry_machine_id.or(cached_machine_id)?;
        let peer = self
            .bootstrap_cache
            .as_ref()?
            .get(&ant_quic::PeerId(machine_id.0))
            .await?;
        (peer.stats.avg_rtt_ms > 0).then_some(peer.stats.avg_rtt_ms)
    }

    /// X0X-0041: build a prefer-newest-connection hint for the gossip-DM
    /// retry loop. Returns `None` when the recipient's machine_id is unknown
    /// (e.g. uninitialised discovery cache); in that case the gossip path
    /// reverts to legacy behaviour and serves out the full backoff window.
    async fn dm_lifecycle_hint(
        &self,
        agent_id: &identity::AgentId,
    ) -> Option<dm_send::DmLifecycleHint> {
        let registry_machine_id = self.direct_messaging.get_machine_id(agent_id).await;
        let cached_machine_id = {
            let cache = self.identity_discovery_cache.read().await;
            cache
                .get(agent_id)
                .map(|entry| entry.machine_id)
                .filter(|machine_id| machine_id.0 != [0_u8; 32])
        };
        let machine_id = registry_machine_id.or(cached_machine_id)?;
        Some(dm_send::DmLifecycleHint {
            recipient_machine_id: machine_id,
            replaced_rx: self.direct_messaging.subscribe_lifecycle_replaced(),
        })
    }

    async fn dm_peer_likely_offline(
        &self,
        agent_id: &identity::AgentId,
    ) -> Option<(f64, Option<u64>)> {
        if self.is_agent_connected(agent_id).await {
            return None;
        }
        let last_seen = {
            let cache = self.identity_discovery_cache.read().await;
            cache.get(agent_id).map(|entry| entry.last_seen)
        }?;
        let now_secs = Self::unix_timestamp_secs();
        let age_secs = now_secs.saturating_sub(last_seen);
        let heartbeat = self.heartbeat_interval_secs.max(1);
        let phi = age_secs as f64 / heartbeat as f64;
        (phi > 8.0).then_some((phi, Some(age_secs.saturating_mul(1000))))
    }

    /// Like [`Self::send_direct`] with caller-provided [`dm::DmSendConfig`].
    ///
    /// # Errors
    ///
    /// See [`dm::DmError`].
    pub async fn send_direct_with_config(
        &self,
        to: &identity::AgentId,
        payload: Vec<u8>,
        config: dm::DmSendConfig,
    ) -> Result<dm::DmReceipt, dm::DmError> {
        if *to == self.identity.agent_id() {
            self.direct_messaging.record_outgoing_started(*to, None);
            if payload.len() > direct::MAX_DIRECT_PAYLOAD_SIZE {
                self.direct_messaging.record_outgoing_failed(*to);
                return Err(dm::DmError::PayloadTooLarge {
                    len: payload.len(),
                    max: direct::MAX_DIRECT_PAYLOAD_SIZE,
                });
            }

            let delivered = self
                .direct_messaging
                .handle_loopback(
                    self.identity.machine_id(),
                    self.identity.agent_id(),
                    payload,
                )
                .await;
            let receipt = dm_send::loopback_receipt();
            self.direct_messaging
                .record_outgoing_succeeded(*to, receipt.path);
            tracing::debug!(
                target: "dm.trace",
                stage = "outbound_send_returned_ok",
                request_id = %hex::encode(receipt.request_id),
                sender = %hex::encode(self.identity.agent_id().as_bytes()),
                recipient = %hex::encode(to.as_bytes()),
                path = "loopback",
                delivered_subscribers = delivered,
            );
            return Ok(receipt);
        }

        let advert_cap = self.capability_store.lookup(to);
        let advert_gossip_ready = advert_cap
            .as_ref()
            .is_some_and(|caps| caps.gossip_inbox && !caps.kem_public_key.is_empty());
        let (cap, cap_source) = if advert_gossip_ready {
            (advert_cap, "advert_cache")
        } else {
            let contact_cap = {
                let contacts = self.contact_store.read().await;
                contacts.get(to).and_then(|contact| {
                    contact
                        .dm_capabilities
                        .as_ref()
                        .filter(|caps| caps.gossip_inbox && !caps.kem_public_key.is_empty())
                        .cloned()
                })
            };
            match contact_cap {
                Some(cap) if advert_cap.is_some() => {
                    (Some(cap), "contact_card_after_unusable_advert")
                }
                Some(cap) => (Some(cap), "contact_card"),
                None if advert_cap.is_some() => (advert_cap, "advert_cache_unusable"),
                None => (None, "none"),
            }
        };
        let gossip_ok = cap
            .as_ref()
            .map(|c| c.gossip_inbox && !c.kem_public_key.is_empty())
            .unwrap_or(false);
        tracing::debug!(
            target: "dm.trace",
            stage = "capability_lookup",
            recipient = %hex::encode(to.as_bytes()),
            hit = cap.is_some(),
            gossip_ok,
            source = cap_source,
            capability_store_entries = self.capability_store.len(),
        );

        // X0X-0070b: seed the relay fallback. Only retain the payload + KEM
        // key clone when the engine is enabled AND we have a key to seal
        // a fresh envelope with. With the default disabled policy this
        // closure never runs - the happy path pays nothing.
        let relay_seed: Option<(Vec<u8>, Vec<u8>)> = if self.peer_relay.policy().enabled {
            cap.as_ref()
                .filter(|c| !c.kem_public_key.is_empty())
                .map(|c| (payload.clone(), c.kem_public_key.clone()))
        } else {
            None
        };

        let rtt_hint_ms = self.dm_peer_rtt_ms(to).await;
        let mut config = config;
        // Direct transport RTT is a valid hint for raw-QUIC work, but it is
        // not a reliable bound for the gossip-inbox ACK path. Keep the
        // conservative default for PubSub-backed DMs unless the caller passed
        // an explicit timeout.
        if !gossip_ok && config.timeout_per_attempt == dm::dm_attempt_timeout(None) {
            config.timeout_per_attempt = dm::dm_attempt_timeout(rtt_hint_ms);
        }
        self.direct_messaging
            .record_outgoing_started(*to, rtt_hint_ms);
        if let Some((phi, last_seen_ms_ago)) = self.dm_peer_likely_offline(to).await {
            self.direct_messaging.record_outgoing_failed(*to);
            return Err(dm::DmError::PeerLikelyOffline {
                phi,
                last_seen_ms_ago,
            });
        }

        let mut preferred_raw_err = None;
        let prefer_newest_grace = std::time::Duration::from_millis(config.prefer_newest_grace_ms);
        let preferred_raw_receipt = if config.prefer_raw_quic_if_connected && !config.require_gossip
        {
            match self
                .send_direct_raw_quic(
                    to,
                    &payload,
                    config.raw_quic_receive_ack_timeout,
                    prefer_newest_grace,
                )
                .await
            {
                Ok(path) => Some(dm_send::raw_quic_receipt_for_path(path)),
                Err(e) => {
                    tracing::debug!(
                        target: "x0x::direct",
                        recipient = %hex::encode(to.as_bytes()),
                        error = %e,
                        "preferred raw-QUIC path unavailable; falling back to capability-aware send"
                    );
                    preferred_raw_err = Some(e);
                    None
                }
            }
        } else {
            None
        };

        let result = if let Some(receipt) = preferred_raw_receipt {
            Ok(receipt)
        } else if preferred_raw_err.as_ref().is_some_and(|err| {
            config.stop_fallback_on_raw_error
                || Self::raw_quic_error_should_stop_fallback(err, gossip_ok)
        }) {
            match preferred_raw_err.take() {
                Some(e) => Err(Self::map_raw_quic_dm_error(e)),
                None => Err(dm::DmError::NoConnectivity(
                    "raw-QUIC send failed before gossip fallback".to_string(),
                )),
            }
        } else if gossip_ok {
            match self.gossip_runtime.as_ref() {
                Some(runtime) => {
                    let signing =
                        gossip::SigningContext::from_keypair(self.identity.agent_keypair());
                    let kem_pub = cap
                        .as_ref()
                        .map(|c| c.kem_public_key.clone())
                        .unwrap_or_default();
                    // X0X-0041: build a lifecycle hint when the recipient's
                    // machine_id is known. The retry loop short-circuits on
                    // `Replaced` for that machine_id rather than serving out
                    // the full backoff window.
                    let lifecycle_hint = self.dm_lifecycle_hint(to).await;
                    dm_send::send_via_gossip(
                        dm_send::DmSendContext {
                            pubsub: std::sync::Arc::clone(runtime.pubsub()),
                            signing: &signing,
                            self_agent_id: self.identity.agent_id(),
                            self_machine_id: self.identity.machine_id(),
                            inflight: std::sync::Arc::clone(&self.dm_inflight_acks),
                        },
                        *to,
                        &kem_pub,
                        payload,
                        &config,
                        lifecycle_hint,
                    )
                    .await
                }
                None => Err(dm::DmError::LocalGossipUnavailable(
                    "send_direct: no gossip runtime configured".to_string(),
                )),
            }
        } else if config.require_gossip {
            Err(dm::DmError::RecipientKeyUnavailable(format!(
                "recipient {} has no gossip DM capability advert",
                hex::encode(to.as_bytes())
            )))
        } else {
            match preferred_raw_err {
                Some(e) => Err(Self::map_raw_quic_dm_error(e)),
                None => self
                    .send_direct_raw_quic(
                        to,
                        &payload,
                        config.raw_quic_receive_ack_timeout,
                        prefer_newest_grace,
                    )
                    .await
                    .map(dm_send::raw_quic_receipt_for_path)
                    .map_err(Self::map_raw_quic_dm_error),
            }
        };

        match result {
            Ok(receipt) => {
                self.direct_messaging
                    .record_outgoing_succeeded(*to, receipt.path);
                // X0X-0070b: every direct-DM success clears the relay engine's
                // per-peer failure history. A peer that had crossed
                // `needs_relay` and now recovers a direct path increments
                // `direct_recovered_after_relay` exactly once - proving the
                // fallback is transient.
                self.peer_relay.record_direct_success(to);
                Ok(receipt)
            }
            Err(direct_err) => {
                self.direct_messaging.record_outgoing_failed(*to);
                // X0X-0070b: count this direct-DM failure on the relay engine.
                // With the default disabled policy `needs_relay` always
                // returns `false` and the fallback below is skipped. With
                // an opted-in policy this drives the relay decision.
                self.peer_relay.record_direct_failure(to);
                // X0X-0070b: relay fallback. We only attempt it when the
                // engine says the peer has now crossed `needs_relay`, and
                // only when we have both a saved payload and a recipient
                // KEM key - without those the relay envelope can't be
                // sealed. On ANY relay-side failure we surface the
                // ORIGINAL direct error so the caller's view stays
                // consistent with the path that was actually tried.
                if let Some((saved_payload, kem_pub)) = relay_seed {
                    if self.peer_relay.needs_relay(to) {
                        match self.try_relay_fallback(to, saved_payload, &kem_pub).await {
                            Ok(relay_receipt) => {
                                self.direct_messaging
                                    .record_outgoing_succeeded(*to, relay_receipt.path);
                                return Ok(relay_receipt);
                            }
                            Err(relay_err) => {
                                tracing::debug!(
                                    target: "x0x::relay",
                                    recipient = %hex::encode(to.as_bytes()),
                                    direct_err = %direct_err,
                                    relay_err = %relay_err,
                                    "X0X-0070b relay fallback failed; surfacing original direct error"
                                );
                            }
                        }
                    }
                }
                Err(direct_err)
            }
        }
    }

    /// X0X-0070b: wrap `payload` in a fresh sealed [`dm::DmEnvelope`] +
    /// [`peer_relay::RelayedDm`], pick a relay candidate via
    /// [`peer_relay::PeerRelay::select_relay`], and forward to that candidate
    /// over the same direct-DM transport using the dedicated
    /// [`network::RELAYED_DM_STREAM_TYPE`] stream-type. The relay verifies
    /// the [`peer_relay::RelayHeader`] signature, confirms it is being
    /// asked to forward (not to be the final recipient), and sends the
    /// inner envelope on to `to` - one hop only, no re-wrapping.
    ///
    /// # Errors
    ///
    /// - [`dm::DmError::NoRelayCandidate`] if no third-party candidate
    ///   exists or the candidate's `MachineId` is not in the discovery
    ///   cache (we need it to address the QUIC peer).
    /// - [`dm::DmError::RelayBuildFailed`] if signing the
    ///   [`peer_relay::RelayHeader`] or parsing the agent secret key
    ///   fails.
    /// - [`dm::DmError::EnvelopeConstruction`] if KEM encapsulation /
    ///   AEAD seal / envelope signature fails (delegates to
    ///   [`dm::EnvelopeBuilder::build_payload_envelope`]).
    /// - [`dm::DmError::NoConnectivity`] if no network is configured.
    /// - [`dm::DmError::PublishFailed`] if the underlying
    ///   [`network::NetworkNode::send_direct_typed`] send fails.
    async fn try_relay_fallback(
        &self,
        to: &identity::AgentId,
        payload: Vec<u8>,
        recipient_kem_public_key: &[u8],
    ) -> Result<dm::DmReceipt, dm::DmError> {
        let sender = self.identity.agent_id();
        let candidates = self.relay_candidates.read().await.clone();
        let Some(relay_agent) = self.peer_relay.select_relay(&candidates, to, &sender) else {
            return Err(dm::DmError::NoRelayCandidate);
        };

        let relay_machine_id = {
            let cache = self.identity_discovery_cache.read().await;
            cache.get(&relay_agent).map(|e| e.machine_id)
        };
        let Some(relay_machine_id) = relay_machine_id else {
            // We have the relay candidate's agent_id but no machine_id -
            // can't address the QUIC peer. Treat as "no candidate" so the
            // caller surfaces the original direct error.
            return Err(dm::DmError::NoRelayCandidate);
        };

        let now = dm::now_unix_ms();
        let expires = now.saturating_add(dm_send::DEFAULT_ENVELOPE_LIFETIME_MS);
        let request_id = dm_send::fresh_request_id();
        let signing = gossip::SigningContext::from_keypair(self.identity.agent_keypair());
        let envelope = dm::EnvelopeBuilder::build_payload_envelope(
            request_id,
            &sender,
            &self.identity.machine_id(),
            to,
            recipient_kem_public_key,
            now,
            expires,
            payload,
            |bytes| signing.sign(bytes).map_err(|e| e.to_string()),
        )?;

        let (sender_pub_bytes, sender_sec_bytes) = self.identity.agent_keypair().to_bytes();
        let sender_secret = ant_quic::MlDsaSecretKey::from_bytes(&sender_sec_bytes)
            .map_err(|e| dm::DmError::RelayBuildFailed(format!("agent secret key: {e:?}")))?;
        let relayed = self
            .peer_relay
            .build_relayed_dm(to, &sender, sender_pub_bytes, now, envelope, |bytes| {
                ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(&sender_secret, bytes)
                    .map(|s| s.as_bytes().to_vec())
                    .map_err(|e| format!("{e:?}"))
            })
            .map_err(dm::DmError::RelayBuildFailed)?;

        let wire = postcard::to_allocvec(&relayed).map_err(|e| {
            dm::DmError::EnvelopeConstruction(format!("relayed envelope postcard: {e}"))
        })?;
        let network = self
            .network
            .as_ref()
            .ok_or_else(|| dm::DmError::NoConnectivity("no network for relay send".to_string()))?;
        let relay_peer_id = ant_quic::PeerId(relay_machine_id.0);
        network
            .send_direct_typed(
                &relay_peer_id,
                sender.as_bytes(),
                network::RELAYED_DM_STREAM_TYPE,
                &wire,
            )
            .await
            .map_err(|e| dm::DmError::PublishFailed(format!("relay send: {e}")))?;

        Ok(dm::DmReceipt {
            request_id,
            accepted_at: std::time::Instant::now(),
            retries_used: 0,
            path: dm::DmPath::Relayed { via: relay_agent },
        })
    }

    /// X0X-0070b: borrow the application-level peer-relay engine. Runtimes
    /// use this to read [`peer_relay::RelayStats`] for telemetry and to
    /// inspect the active [`peer_relay::RelayPolicy`].
    #[must_use]
    pub fn peer_relay(&self) -> &peer_relay::PeerRelay {
        &self.peer_relay
    }

    /// X0X-0070b: snapshot the current relay candidate set. Returns a
    /// freshly-cloned vector so the caller never holds the underlying
    /// `RwLock`. The set is seeded from `NetworkConfig.peer_relay.candidates`
    /// at build time; the gossip-announce subscriber (a follow-up commit)
    /// extends it at runtime.
    pub async fn relay_candidates(&self) -> Vec<identity::AgentId> {
        self.relay_candidates.read().await.clone()
    }

    /// Legacy raw-QUIC direct-send path. Internal fallback only.
    ///
    /// X0X-0053: `prefer_newest_grace` is the bounded post-Replaced reissue
    /// grace — the maximum time we wait for the new connection's
    /// `is_connected` to flip true after a same-peer `Replaced` event fires
    /// mid-send before we reissue. Setting it to zero disables the grace and
    /// reissues immediately on Replaced (or fails if the new connection is
    /// not yet live).
    ///
    /// On the ACKed raw path, the in-flight `send_with_receive_ack` future
    /// is raced against `lifecycle_replaced_rx.recv()` filtered for the
    /// target peer's machine_id. On Replaced for the target peer, the
    /// in-flight send is abandoned and reissued once against the new
    /// generation. If the reissue also fails, the standard error is
    /// returned. This closes the X0X-0041 coverage gap surfaced by the
    /// Phase A bisect (P1 finding in
    /// `proofs/sota-borrow-phaseA-bisect-20260508T214634Z/ANALYSIS.md` §0.1).
    async fn send_direct_raw_quic(
        &self,
        agent_id: &identity::AgentId,
        payload: &[u8],
        receive_ack_timeout: Option<std::time::Duration>,
        prefer_newest_grace: std::time::Duration,
    ) -> error::NetworkResult<dm::DmPath> {
        let send_start = std::time::Instant::now();
        let agent_prefix = network::hex_prefix(&agent_id.0, 4);
        let self_prefix = network::hex_prefix(&self.identity.agent_id().0, 4);
        let bytes = payload.len();
        let digest = direct::dm_payload_digest_hex(payload);
        let target_path_label = if receive_ack_timeout.is_some() {
            "raw_quic_acked"
        } else {
            "raw_quic"
        };

        let network = self.network.as_ref().ok_or_else(|| {
            tracing::warn!(
                target: "x0x::direct",
                stage = "send",
                agent_prefix = %crate::logging::LogHexId::agent(&agent_prefix),
                outcome = "err_no_network",
                "network not initialised"
            );
            error::NetworkError::NodeCreation("network not initialized".to_string())
        })?;

        // Resolve the best known machine_id, preferring a machine that is
        // actually connected right now. Discovery cache entries can lag behind
        // the direct-messaging registry when an inbound connection is accepted
        // and later reconciled from transport events.
        let cached_machine_id = {
            let cache = self.identity_discovery_cache.read().await;
            cache
                .get(agent_id)
                .map(|d| d.machine_id)
                .filter(|m| m.0 != [0u8; 32]) // Ignore placeholder zeroed IDs
        };
        let registry_machine_id = self.direct_messaging.get_machine_id(agent_id).await;

        let (machine_id, resolution) = match (cached_machine_id, registry_machine_id) {
            (Some(id), _) if network.is_connected(&ant_quic::PeerId(id.0)).await => {
                (id, "cached_connected")
            }
            (_, Some(id)) if network.is_connected(&ant_quic::PeerId(id.0)).await => {
                if cached_machine_id != Some(id) {
                    let mut cache = self.identity_discovery_cache.write().await;
                    if let Some(entry) = cache.get_mut(agent_id) {
                        entry.machine_id = id;
                    }
                }
                (id, "registry_connected")
            }
            (Some(id), None) => (id, "cached_not_connected"),
            (Some(id), Some(_)) => (id, "cached_both_disconnected"),
            (None, Some(id)) => (id, "registry_not_connected"),
            (None, None) => {
                tracing::debug!(
                    target: "x0x::direct",
                    stage = "send",
                    %agent_prefix,
                    resolution = "last_resort_connect",
                    "no machine_id known; triggering connect_to_agent"
                );
                let _ = self.connect_to_agent(agent_id).await;
                let id = self
                    .direct_messaging
                    .get_machine_id(agent_id)
                    .await
                    .ok_or_else(|| {
                        tracing::warn!(
                            target: "x0x::direct",
                            stage = "send",
                            agent_prefix = %crate::logging::LogHexId::agent(&agent_prefix),
                            outcome = "err_agent_not_found",
                            dur_ms = send_start.elapsed().as_millis() as u64,
                            "no machine_id after connect_to_agent"
                        );
                        error::NetworkError::AgentNotFound(agent_id.0)
                    })?;
                (id, "post_connect")
            }
        };

        // Check if connected. ant-quic's live connection table is the source
        // of truth; the x0x lifecycle table is a derived fast-fail cache and
        // can briefly lag during connection replacement/supersede churn. Raw
        // sends best-effort clear stale lifecycle blocks when ant-quic is live;
        // capability-first gossip sends may leave cosmetic stale diagnostics
        // until a raw probe/send path observes the live connection.
        let ant_peer_id = ant_quic::PeerId(machine_id.0);
        let machine_prefix = network::hex_prefix(&machine_id.0, 4);
        let mut connected = network.is_connected(&ant_peer_id).await;

        // X0X-0033: when machine_id is known (resolved from cache or registry)
        // but ant-quic isn't currently connected, the X0X-0031 send-readiness
        // hardening (single-flight per peer + bounded concurrency, falling
        // through to bootstrap-cache redial) used to sit behind this check
        // unreachable from the raw path. Drive it explicitly here so the raw
        // direct path attempts repair before bailing with AgentNotConnected.
        // Skip when resolution == "post_connect" (last-resort branch already
        // invoked connect_to_agent above).
        let mut repair_outcome: Option<&'static str> = None;
        if !connected && resolution != "post_connect" {
            const REPAIR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
            let outcome = match tokio::time::timeout(
                REPAIR_TIMEOUT,
                network.ensure_peer_send_ready(&ant_peer_id),
            )
            .await
            {
                Ok(Ok(())) => "repaired",
                Ok(Err(_)) => "repair_failed",
                Err(_) => "repair_timeout",
            };
            repair_outcome = Some(outcome);
            tracing::debug!(
                target: "x0x::direct",
                stage = "send",
                %agent_prefix,
                %machine_prefix,
                resolution,
                outcome,
                "send-readiness repair on disconnected peer"
            );
            connected = network.is_connected(&ant_peer_id).await;
        }

        // X0X-0051 / X0X-0053: the X0X-0041 prefer-newest-grace block was
        // removed in x0x 0.19.33. It only fired when `is_connected` returned
        // false before the send, never racing `Replaced` against the in-flight
        // `send_with_receive_ack` below — so it had a coverage gap on the
        // ACKed raw-DM path the Phase A harness exercises. The proper
        // re-implementation (race in-flight send against same-peer Replaced)
        // is tracked in X0X-0053. This path now falls straight through to the
        // standard !connected error handling.

        if connected {
            if let Some(reason) = self.direct_messaging.lifecycle_block_reason(&machine_id) {
                tracing::warn!(
                    target: "x0x::direct",
                    stage = "send",
                    agent_prefix = %crate::logging::LogHexId::agent(&agent_prefix),
                    machine_prefix = %crate::logging::LogHexId::new("machine", &machine_prefix),
                    resolution,
                    ?repair_outcome,
                    reason = %reason,
                    "ignoring stale lifecycle block because ant-quic reports a live connection"
                );
                self.direct_messaging
                    .record_lifecycle_established(machine_id, None);
            }
        } else {
            if let Some(reason) = self.direct_messaging.lifecycle_block_reason(&machine_id) {
                tracing::warn!(
                    target: "x0x::direct",
                    stage = "send",
                    agent_prefix = %crate::logging::LogHexId::agent(&agent_prefix),
                    machine_prefix = %crate::logging::LogHexId::new("machine", &machine_prefix),
                    resolution,
                    ?repair_outcome,
                    outcome = "err_peer_disconnected",
                    reason = %reason,
                    dur_ms = send_start.elapsed().as_millis() as u64,
                    "lifecycle watcher says peer is disconnected"
                );
                return Err(error::NetworkError::ConnectionFailed(format!(
                    "peer disconnected: {reason}"
                )));
            }
            tracing::warn!(
                target: "x0x::direct",
                stage = "send",
                agent_prefix = %crate::logging::LogHexId::agent(&agent_prefix),
                machine_prefix = %crate::logging::LogHexId::new("machine", &machine_prefix),
                resolution,
                ?repair_outcome,
                outcome = "err_not_connected",
                bytes,
                dur_ms = send_start.elapsed().as_millis() as u64,
                "machine_id resolved but peer not currently connected after repair attempt"
            );
            return Err(error::NetworkError::AgentNotConnected(agent_id.0));
        }

        tracing::debug!(
            target: "dm.trace",
            stage = "path_chosen",
            sender = %hex::encode(self.identity.agent_id().as_bytes()),
            recipient = %hex::encode(agent_id.as_bytes()),
            machine_id = %hex::encode(machine_id.as_bytes()),
            path = target_path_label,
            bytes,
            digest = %digest,
        );

        // Send via network layer. Prefer receive-pipeline ACK when configured:
        // success then means the remote ant-quic reader drained the direct
        // message bytes, not merely that the local socket accepted them.
        let send_result = if let Some(timeout) = receive_ack_timeout {
            let wire = direct::DirectMessaging::encode_message(&self.identity.agent_id(), payload)?;
            tracing::debug!(
                target: "dm.trace",
                stage = "wire_encoded",
                sender = %hex::encode(self.identity.agent_id().as_bytes()),
                recipient = %hex::encode(agent_id.as_bytes()),
                path = "raw_quic_acked",
                bytes = wire.len(),
                payload_bytes = bytes,
                digest = %digest,
            );
            // X0X-0053: race the in-flight send_with_receive_ack against
            // same-peer Replaced. On Replaced for this machine_id, abandon
            // the in-flight future (Quinn streams are drop-safe — see
            // ant-quic's send_with_receive_ack contract) and reissue once
            // against the new generation. The reissue does not race again;
            // a healthy peer should converge in a single supersede cycle.
            self.send_ack_racing_replaced(
                network.as_ref(),
                ant_peer_id,
                machine_id,
                &wire,
                timeout,
                prefer_newest_grace,
                agent_id,
            )
            .await
        } else {
            tracing::debug!(
                target: "dm.trace",
                stage = "wire_encoded",
                sender = %hex::encode(self.identity.agent_id().as_bytes()),
                recipient = %hex::encode(agent_id.as_bytes()),
                path = "raw_quic",
                bytes,
                digest = %digest,
            );
            network
                .send_direct(&ant_peer_id, &self.identity.agent_id().0, payload)
                .await
                .map(|()| dm::DmPath::RawQuic)
        };

        match send_result {
            Ok(path) => {
                let path_label = match path {
                    dm::DmPath::Loopback => "loopback",
                    dm::DmPath::RawQuic => "raw_quic",
                    dm::DmPath::RawQuicAcked => "raw_quic_acked",
                    dm::DmPath::GossipInbox => "gossip_inbox",
                    dm::DmPath::Relayed { .. } => "relayed",
                };
                tracing::debug!(
                    target: "dm.trace",
                    stage = "outbound_send_returned_ok",
                    sender = %hex::encode(self.identity.agent_id().as_bytes()),
                    recipient = %hex::encode(agent_id.as_bytes()),
                    machine_id = %hex::encode(machine_id.as_bytes()),
                    path = path_label,
                    bytes,
                    digest = %digest,
                    dur_ms = send_start.elapsed().as_millis() as u64,
                );
                tracing::info!(
                    target: "x0x::direct",
                    stage = "send",
                    from = %self_prefix,
                    to = %agent_prefix,
                    %machine_prefix,
                    resolution,
                    bytes,
                    dur_ms = send_start.elapsed().as_millis() as u64,
                    outcome = "ok",
                    path = ?path,
                    "direct message sent"
                );
                Ok(path)
            }
            Err(e) => {
                tracing::warn!(
                    target: "x0x::direct",
                    stage = "send",
                    from = %self_prefix,
                    to = %agent_prefix,
                    machine_prefix = %crate::logging::LogHexId::new("machine", &machine_prefix),
                    resolution,
                    bytes,
                    dur_ms = send_start.elapsed().as_millis() as u64,
                    outcome = "err_transport",
                    error = %e,
                    "transport send_direct failed"
                );
                // A receive-ACK-path failure on a connection that still reads
                // as connected means the connection is a zombie: the remote
                // endpoint is gone (supersede/NAT loss without a lifecycle
                // event) yet `is_connected` keeps steering every retry back
                // onto it via `cached_connected`. Tear it down so the next
                // attempt fails the fast path and takes the X0X-0031/0033
                // send-readiness repair (fresh dial) instead of re-sending
                // into the same dead connection until the caller's deadline.
                if receive_ack_timeout.is_some() && network.is_connected(&ant_peer_id).await {
                    match network.disconnect(&ant_peer_id).await {
                        Ok(()) => tracing::info!(
                            target: "x0x::direct",
                            stage = "send",
                            to = %agent_prefix,
                            %machine_prefix,
                            "tore down zombie connection after acked send failure; retry will redial"
                        ),
                        Err(de) => tracing::debug!(
                            target: "x0x::direct",
                            stage = "send",
                            to = %agent_prefix,
                            %machine_prefix,
                            error = %de,
                            "failed to tear down zombie connection after acked send failure"
                        ),
                    }
                }
                Err(e)
            }
        }
    }

    /// X0X-0053: race the in-flight `send_with_receive_ack` against same-peer
    /// `Replaced`. On Replaced for the target peer, abandon the in-flight
    /// future, briefly wait for the new connection's `is_connected` to flip
    /// true (bounded by `prefer_newest_grace`), then reissue once against
    /// the new generation. The reissue does not race again — a healthy peer
    /// converges in a single supersede cycle. Lag handling on the broadcast
    /// channel mirrors `dm_send::wait_for_ack_or_backoff_or_replaced` —
    /// drain to current and re-subscribe.
    #[allow(clippy::too_many_arguments)]
    async fn send_ack_racing_replaced(
        &self,
        network: &network::NetworkNode,
        ant_peer_id: ant_quic::PeerId,
        machine_id: identity::MachineId,
        wire: &[u8],
        timeout: std::time::Duration,
        prefer_newest_grace: std::time::Duration,
        agent_id: &identity::AgentId,
    ) -> error::NetworkResult<dm::DmPath> {
        use tokio::sync::broadcast::error::RecvError;
        use tokio::sync::broadcast::error::TryRecvError as BroadcastTryRecvError;

        // Subscribe BEFORE issuing the send so any Replaced that fires
        // mid-send is delivered to this receiver and not dropped.
        let mut replaced_rx = self.direct_messaging.subscribe_lifecycle_replaced();
        let pre_send_generation = self.direct_messaging.current_generation(&machine_id);

        let agent_prefix = network::hex_prefix(&agent_id.0, 4);
        let machine_prefix = network::hex_prefix(&machine_id.0, 4);
        let self_prefix = network::hex_prefix(&self.identity.agent_id().0, 4);

        let ack_race_test_hook = self.direct_messaging.raw_quic_ack_race_test_hook();

        // First attempt: race send_with_receive_ack against same-peer Replaced.
        let send_fut = async {
            if let Some(hook) = ack_race_test_hook.as_ref() {
                hook.notify_first_attempt_started();
            }
            let result = network
                .send_with_receive_ack(ant_peer_id, wire, timeout)
                .await;
            if let Some(hook) = ack_race_test_hook.as_ref() {
                hook.hold_first_attempt_result().await;
            }
            result
        };
        tokio::pin!(send_fut);

        let superseded_to: u64;

        loop {
            tokio::select! {
                biased;
                send_result = &mut send_fut => {
                    // X0X-0053: even when send_fut completes (Ok or Err)
                    // first, drain the broadcast for any queued Replaced
                    // event for our peer. On Err with a queued supersede,
                    // we treat the failure as a casualty of the supersede
                    // race and reissue against the new generation —
                    // exactly the production case where the in-flight ACK
                    // exchange errors out fast on the dying connection
                    // milliseconds before the new connection is registered.
                    match send_result {
                        Some(Ok(())) => return Ok(dm::DmPath::RawQuicAcked),
                        Some(Err(e)) => {
                            // Drain any queued Replaced for our peer.
                            let mut queued_supersede: Option<u64> = None;
                            loop {
                                match replaced_rx.try_recv() {
                                    Ok((m, gen)) if m == machine_id => {
                                        queued_supersede = Some(gen);
                                    }
                                    Ok(_) => continue,
                                    Err(BroadcastTryRecvError::Empty)
                                    | Err(BroadcastTryRecvError::Closed)
                                    | Err(BroadcastTryRecvError::Lagged(_)) => break,
                                }
                            }
                            if let Some(gen) = queued_supersede {
                                superseded_to = gen;
                                break;
                            }
                            let reason = format!("send_with_receive_ack failed: {e}");
                            return if Self::raw_quic_ack_receive_backpressured(&reason) {
                                Err(error::NetworkError::RemoteReceiveBackpressured(reason))
                            } else {
                                Err(error::NetworkError::ConnectionFailed(reason))
                            };
                        }
                        None => return Err(error::NetworkError::NodeCreation(
                            "network node not initialized".to_string(),
                        )),
                    }
                }
                replaced = replaced_rx.recv() => {
                    match replaced {
                        Ok((m, gen)) if m == machine_id => {
                            superseded_to = gen;
                            break;
                        }
                        Ok(_) => continue,
                        Err(RecvError::Lagged(_)) => {
                            // Drain the channel for any pending event for our
                            // peer; if found, treat as supersede.
                            let mut found: Option<u64> = None;
                            loop {
                                match replaced_rx.try_recv() {
                                    Ok((m, gen)) if m == machine_id => {
                                        found = Some(gen);
                                        break;
                                    }
                                    Ok(_) => continue,
                                    Err(BroadcastTryRecvError::Empty)
                                    | Err(BroadcastTryRecvError::Closed)
                                    | Err(BroadcastTryRecvError::Lagged(_)) => break,
                                }
                            }
                            if let Some(gen) = found {
                                superseded_to = gen;
                                break;
                            }
                            // No event for our peer — re-subscribe to clear
                            // lag state and keep waiting.
                            replaced_rx = self
                                .direct_messaging
                                .subscribe_lifecycle_replaced();
                            continue;
                        }
                        Err(RecvError::Closed) => {
                            // Channel closed — no further supersede signals.
                            // Fall through to await the in-flight send to its
                            // natural completion.
                            let result = (&mut send_fut).await;
                            return match result {
                                Some(Ok(())) => Ok(dm::DmPath::RawQuicAcked),
                                Some(Err(e)) => {
                                    let reason =
                                        format!("send_with_receive_ack failed: {e}");
                                    if Self::raw_quic_ack_receive_backpressured(&reason) {
                                        Err(error::NetworkError::RemoteReceiveBackpressured(reason))
                                    } else {
                                        Err(error::NetworkError::ConnectionFailed(reason))
                                    }
                                }
                                None => Err(error::NetworkError::NodeCreation(
                                    "network node not initialized".to_string(),
                                )),
                            };
                        }
                    }
                }
            }
        }

        // Reached here only via a confirmed same-peer Replaced. The pinned
        // in-flight send future is no longer polled and will be dropped at
        // scope exit (Quinn streams are drop-safe — abandoning the future
        // simply releases the local stream handle; the underlying connection
        // is the one ant-quic is replacing). Wait briefly for the new
        // connection's `is_connected` to flip true before reissuing.
        let new_generation = superseded_to;
        if let Some(hook) = ack_race_test_hook.as_ref() {
            hook.notify_replaced_short_circuit();
        }
        tracing::debug!(
            target: "dm.trace",
            stage = "raw_quic_ack_replaced_short_circuit",
            from = %self_prefix,
            to = %agent_prefix,
            %machine_prefix,
            pre_send_generation = ?pre_send_generation,
            new_generation,
            grace_ms = prefer_newest_grace.as_millis() as u64,
            "X0X-0053: same-peer Replaced fired during in-flight send_with_receive_ack; abandoning and reissuing",
        );

        // Bounded grace: poll for the new connection to be live before
        // reissuing. If it never flips inside the grace window, return the
        // standard not-connected error and let the caller fall back.
        if !prefer_newest_grace.is_zero() {
            let grace_deadline = tokio::time::Instant::now() + prefer_newest_grace;
            const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);
            while tokio::time::Instant::now() < grace_deadline {
                if network.is_connected(&ant_peer_id).await {
                    break;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }

        if !network.is_connected(&ant_peer_id).await {
            return Err(error::NetworkError::AgentNotConnected(agent_id.0));
        }

        // Reissue once against the new generation. No further race — a
        // healthy peer should converge in a single supersede cycle.
        match network
            .send_with_receive_ack(ant_peer_id, wire, timeout)
            .await
        {
            Some(Ok(())) => Ok(dm::DmPath::RawQuicAcked),
            Some(Err(e)) => {
                let reason = format!("send_with_receive_ack failed: {e}");
                if Self::raw_quic_ack_receive_backpressured(&reason) {
                    Err(error::NetworkError::RemoteReceiveBackpressured(reason))
                } else {
                    Err(error::NetworkError::ConnectionFailed(reason))
                }
            }
            None => Err(error::NetworkError::NodeCreation(
                "network node not initialized".to_string(),
            )),
        }
    }

    fn raw_quic_error_should_stop_fallback(
        err: &error::NetworkError,
        gossip_available: bool,
    ) -> bool {
        match err {
            // These are semantic/local failures; trying the gossip path cannot
            // make the payload smaller or create a missing local network node.
            error::NetworkError::PayloadTooLarge { .. } | error::NetworkError::NodeCreation(_) => {
                true
            }
            error::NetworkError::ConnectionFailed(reason)
                if reason.starts_with("peer disconnected:")
                    || reason.starts_with("send_with_receive_ack failed:") =>
            {
                !gossip_available
            }
            error::NetworkError::RemoteReceiveBackpressured(_) => !gossip_available,
            error::NetworkError::ConnectionClosed(_)
            | error::NetworkError::ConnectionReset(_)
            | error::NetworkError::NotConnected(_) => !gossip_available,
            _ => false,
        }
    }

    fn raw_quic_ack_receive_backpressured(reason: &str) -> bool {
        reason.contains("Remote receive pipeline rejected payload: Backpressured")
    }

    fn map_raw_quic_dm_error(err: error::NetworkError) -> dm::DmError {
        match err {
            error::NetworkError::AgentNotFound(_) => {
                dm::DmError::RecipientKeyUnavailable(err.to_string())
            }
            error::NetworkError::AgentNotConnected(_)
            | error::NetworkError::NotConnected(_)
            | error::NetworkError::ConnectionClosed(_)
            | error::NetworkError::ConnectionReset(_) => dm::DmError::PeerDisconnected {
                reason: err.to_string(),
            },
            error::NetworkError::ConnectionFailed(reason)
                if reason.starts_with("peer disconnected:")
                    || reason.starts_with("send_with_receive_ack failed:") =>
            {
                dm::DmError::PeerDisconnected { reason }
            }
            error::NetworkError::RemoteReceiveBackpressured(reason) => {
                dm::DmError::ReceiverBackpressured { reason }
            }
            error::NetworkError::PayloadTooLarge { size, max } => {
                dm::DmError::PayloadTooLarge { len: size, max }
            }
            error::NetworkError::NodeCreation(reason) => dm::DmError::NoConnectivity(reason),
            other => dm::DmError::PublishFailed(other.to_string()),
        }
    }

    /// Receive the next direct message from any connected agent.
    ///
    /// Blocks until a direct message is received.
    ///
    /// # Security Note
    ///
    /// This method does **not** apply trust filtering from `ContactStore`.
    /// Messages from blocked agents will still be delivered. Use
    /// [`recv_direct_annotated()`](Self::recv_direct_annotated) if you need
    /// trust-based filtering.
    ///
    /// # Returns
    ///
    /// The received [`DirectMessage`] containing sender, payload, and timestamp.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// loop {
    ///     if let Some(msg) = agent.recv_direct().await {
    ///         println!("From {:?}: {:?}", msg.sender, msg.payload_str());
    ///     }
    /// }
    /// ```
    pub async fn recv_direct(&self) -> Option<direct::DirectMessage> {
        self.recv_direct_inner().await
    }

    /// Receive the next direct message, filtering by trust level.
    ///
    /// All messages now carry pre-computed `verified` and `trust_decision`
    /// fields from the identity discovery cache and contact store. This
    /// method passes through all messages — applications should inspect
    /// `msg.trust_decision` and `msg.verified` to decide how to handle
    /// each message.
    ///
    /// # Returns
    ///
    /// The received [`DirectMessage`], or `None` if the channel closes.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// loop {
    ///     if let Some(msg) = agent.recv_direct_annotated().await {
    ///         match msg.trust_decision {
    ///             Some(TrustDecision::RejectBlocked) => continue, // skip
    ///             Some(TrustDecision::Accept) if msg.verified => { /* trusted */ }
    ///             _ => { /* handle accordingly */ }
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn recv_direct_annotated(&self) -> Option<direct::DirectMessage> {
        self.recv_direct_inner().await
    }

    /// Internal helper for receiving direct messages.
    ///
    /// Reads from the `DirectMessaging` internal channel, which is fed by
    /// the background `start_direct_listener` task. This ensures there is
    /// only ONE consumer of `network.recv_direct()` (the listener), avoiding
    /// message-stealing races.
    async fn recv_direct_inner(&self) -> Option<direct::DirectMessage> {
        self.direct_messaging.recv().await
    }

    /// Subscribe to direct messages.
    ///
    /// Returns a receiver that can be cloned for multiple consumers.
    /// Messages are broadcast to all receivers.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut rx = agent.subscribe_direct();
    /// tokio::spawn(async move {
    ///     while let Some(msg) = rx.recv().await {
    ///         println!("Direct message: {:?}", msg);
    ///     }
    /// });
    /// ```
    pub fn subscribe_direct(&self) -> direct::DirectMessageReceiver {
        self.direct_messaging.subscribe()
    }

    /// Get the direct messaging infrastructure.
    ///
    /// Provides low-level access to connection tracking and agent mappings.
    pub fn direct_messaging(&self) -> &std::sync::Arc<direct::DirectMessaging> {
        &self.direct_messaging
    }

    /// Check if an agent is currently connected for direct messaging.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The agent to check.
    ///
    /// # Returns
    ///
    /// `true` if a QUIC connection exists to this agent's machine.
    pub async fn is_agent_connected(&self, agent_id: &identity::AgentId) -> bool {
        let Some(network) = &self.network else {
            return false;
        };

        // Look up machine_id from discovery cache
        let machine_id = {
            let cache = self.identity_discovery_cache.read().await;
            cache.get(agent_id).map(|d| d.machine_id)
        };

        match machine_id {
            Some(mid) => {
                let ant_peer_id = ant_quic::PeerId(mid.0);
                network.is_connected(&ant_peer_id).await
            }
            None => false,
        }
    }

    /// Get list of currently connected agents.
    ///
    /// Returns agents that have been discovered and are currently connected
    /// via QUIC transport.
    pub async fn connected_agents(&self) -> Vec<identity::AgentId> {
        let Some(network) = &self.network else {
            return Vec::new();
        };

        let connected_peers = network.connected_peers().await;
        let cache = self.identity_discovery_cache.read().await;

        // Find agents whose machine_id matches a connected peer
        cache
            .values()
            .filter(|agent| {
                let ant_peer_id = ant_quic::PeerId(agent.machine_id.0);
                connected_peers.contains(&ant_peer_id)
            })
            .map(|agent| agent.agent_id)
            .collect()
    }

    /// Attach a contact store for trust-based message filtering.
    ///
    /// When set, the gossip pub/sub layer will:
    /// - Drop messages from `Blocked` senders (don't deliver, don't rebroadcast)
    /// - Annotate messages with the sender's trust level for consumers
    ///
    /// Without a contact store, all messages pass through (open relay mode).
    pub fn set_contacts(&self, store: std::sync::Arc<tokio::sync::RwLock<contacts::ContactStore>>) {
        if let Some(runtime) = &self.gossip_runtime {
            let pubsub = runtime.pubsub();
            pubsub.set_contacts(store);
            // Thread the authoritative gossiped RevocationSet into pub/sub
            // delivery so a gossiped revocation closes the subscribe path
            // (issue #191 gap 3). Wired here so every runtime that sets
            // contacts also sets revocation — they share the same lifecycle.
            pubsub.set_revocation_set(self.revocation_set());
        }
    }

    /// Announce this agent's identity on the network discovery topic.
    ///
    /// By default, announcements include agent + machine identity only.
    /// Human identity disclosure is opt-in and requires explicit consent.
    ///
    /// # Arguments
    ///
    /// * `include_user_identity` - Whether to include `user_id` and certificate
    /// * `human_consent` - Must be `true` when disclosing user identity
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Gossip runtime is not initialized
    /// - Human identity disclosure is requested without explicit consent
    /// - Human identity disclosure is requested but no user identity is configured
    /// - Serialization or publish fails
    pub async fn announce_identity(
        &self,
        include_user_identity: bool,
        human_consent: bool,
    ) -> error::Result<()> {
        let runtime = self.gossip_runtime.as_ref().ok_or_else(|| {
            error::IdentityError::Storage(std::io::Error::other(
                "gossip runtime not initialized - configure agent with network first",
            ))
        })?;

        self.start_identity_listener().await?;

        let network_status = if let Some(network) = self.network.as_ref() {
            network.node_status().await
        } else {
            None
        };
        let assist_snapshot = network_status
            .as_ref()
            .map(AnnouncementAssistSnapshot::from_node_status)
            .unwrap_or_default();

        // Include ALL routable addresses (IPv4 and IPv6).
        let mut addresses = if let Some(network) = self.network.as_ref() {
            match network_status.as_ref() {
                Some(status) if !status.external_addrs.is_empty() => status.external_addrs.clone(),
                _ => match network.routable_addr().await {
                    Some(addr) => vec![addr],
                    None => self.announcement_addresses(),
                },
            }
        } else {
            self.announcement_addresses()
        };
        // Detect addresses locally via UDP socket tricks.
        // ant-quic discovers public IPv4 via OBSERVED_ADDRESS from peers.
        // IPv6 is globally routable (no NAT), so we probe locally.
        //
        // For locally-probed addresses (IPv6 and LAN IPv4), use the actual
        // bound port from the QUIC endpoint — NOT the first external address
        // port (which is NAT-mapped) and NOT the config bind port (which may
        // be 0 for OS-assigned ports).
        let bind_port = if let Some(network) = self.network.as_ref() {
            network.bound_addr().await.map(|a| a.port()).unwrap_or(5483)
        } else {
            5483
        };

        // IPv6 probe
        if let Ok(sock) = std::net::UdpSocket::bind("[::]:0") {
            if sock.connect("[2001:4860:4860::8888]:80").is_ok() {
                if let Ok(local) = sock.local_addr() {
                    if let std::net::IpAddr::V6(v6) = local.ip() {
                        let segs = v6.segments();
                        let is_global = (segs[0] & 0xffc0) != 0xfe80
                            && (segs[0] & 0xff00) != 0xfd00
                            && !v6.is_loopback();
                        if is_global {
                            let v6_addr =
                                std::net::SocketAddr::new(std::net::IpAddr::V6(v6), bind_port);
                            if !addresses.contains(&v6_addr) {
                                addresses.push(v6_addr);
                            }
                        }
                    }
                }
            }
        }

        for addr in collect_local_interface_addrs(bind_port) {
            if !addresses.contains(&addr) {
                addresses.push(addr);
            }
        }

        let allow_local_scope = self
            .network
            .as_ref()
            .is_some_and(|network| allow_local_discovery_addresses(network.config()));
        // Same rule as HeartbeatContext::announce(): global bootstrap partitions
        // publish only globally-routable endpoints, while explicit local/testnet
        // partitions may publish LAN/loopback hints for same-partition peers.
        addresses = filter_discovery_announcement_addrs(addresses, allow_local_scope);

        // Emit coordinator / relay hints only when direct inbound is not
        // known to work. See HeartbeatContext::announce() for rationale.
        let (reachable_via, relay_candidates) = if assist_snapshot.can_receive_direct == Some(true)
        {
            (Vec::new(), Vec::new())
        } else if let Some(network) = self.network.as_ref() {
            collect_coordinator_hints(
                network.as_ref(),
                &self.machine_discovery_cache,
                self.machine_id(),
            )
            .await
        } else {
            (Vec::new(), Vec::new())
        };

        let announcement =
            self.build_identity_announcement_with_addrs(IdentityAnnouncementBuildOptions {
                include_user_identity,
                human_consent,
                addresses,
                assist_snapshot: Some(&assist_snapshot),
                reachable_via,
                relay_candidates,
                allow_local_scope,
            })?;
        tracing::debug!(
            target: "x0x::discovery",
            announcement_kind = "explicit",
            machine_prefix = %network::hex_prefix(&announcement.machine_id.0, 4),
            addr_total = announcement.addresses.len(),
            nat_type = announcement.nat_type.as_deref().unwrap_or("unknown"),
            can_receive_direct = ?announcement.can_receive_direct,
            relay_capable = ?announcement.is_relay,
            coordinator_capable = ?announcement.is_coordinator,
            relay_active = ?assist_snapshot.relay_active,
            coordinator_active = ?assist_snapshot.coordinator_active,
            "publishing identity announcement"
        );

        let machine_announcement = build_machine_announcement_for_identity(
            &self.identity,
            announcement.addresses.clone(),
            announcement.announced_at,
            Some(&assist_snapshot),
            announcement.reachable_via.clone(),
            announcement.relay_candidates.clone(),
            allow_local_scope,
        )?;
        tracing::debug!(
            target: "x0x::discovery",
            announcement_kind = "machine_explicit",
            machine_prefix = %network::hex_prefix(&machine_announcement.machine_id.0, 4),
            addr_total = machine_announcement.addresses.len(),
            nat_type = machine_announcement.nat_type.as_deref().unwrap_or("unknown"),
            can_receive_direct = ?machine_announcement.can_receive_direct,
            relay_capable = ?machine_announcement.is_relay,
            coordinator_capable = ?machine_announcement.is_coordinator,
            reachable_via_count = machine_announcement.reachable_via.len(),
            relay_candidate_count = machine_announcement.relay_candidates.len(),
            "publishing machine announcement"
        );
        let machine_payload =
            bytes::Bytes::from(bincode::serialize(&machine_announcement).map_err(|e| {
                error::IdentityError::Serialization(format!(
                    "failed to serialize machine announcement: {e}"
                ))
            })?);
        runtime
            .pubsub()
            .publish(
                shard_topic_for_machine(&machine_announcement.machine_id),
                machine_payload.clone(),
            )
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "failed to publish machine announcement to shard topic: {e}"
                )))
            })?;
        runtime
            .pubsub()
            .publish(MACHINE_ANNOUNCE_TOPIC.to_string(), machine_payload)
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "failed to publish machine announcement: {e}"
                )))
            })?;

        let encoded = bincode::serialize(&announcement).map_err(|e| {
            error::IdentityError::Serialization(format!(
                "failed to serialize identity announcement: {e}"
            ))
        })?;

        let payload = bytes::Bytes::from(encoded);

        // Publish to shard topic first (future-proof routing).
        let shard_topic = shard_topic_for_agent(&announcement.agent_id);
        runtime
            .pubsub()
            .publish(shard_topic, payload.clone())
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "failed to publish identity announcement to shard topic: {e}"
                )))
            })?;

        // Also publish to legacy broadcast topic for backward compatibility.
        runtime
            .pubsub()
            .publish(IDENTITY_ANNOUNCE_TOPIC.to_string(), payload)
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "failed to publish identity announcement: {e}"
                )))
            })?;

        let now = Self::unix_timestamp_secs();
        upsert_discovered_machine(
            &self.machine_discovery_cache,
            DiscoveredMachine::from_machine_announcement(
                &machine_announcement,
                machine_announcement.addresses.clone(),
                now,
            ),
        )
        .await;
        let discovered_agent = DiscoveredAgent {
            agent_id: announcement.agent_id,
            machine_id: announcement.machine_id,
            user_id: announcement.user_id,
            addresses: announcement.addresses.clone(),
            announced_at: announcement.announced_at,
            last_seen: now,
            machine_public_key: announcement.machine_public_key.clone(),
            nat_type: announcement.nat_type.clone(),
            can_receive_direct: announcement.can_receive_direct,
            is_relay: announcement.is_relay,
            is_coordinator: announcement.is_coordinator,
            reachable_via: announcement.reachable_via.clone(),
            relay_candidates: announcement.relay_candidates.clone(),
            cert_not_after: None,
            agent_certificate: None,
        };
        upsert_discovered_machine_from_agent(&self.machine_discovery_cache, &discovered_agent)
            .await;
        upsert_discovered_agent(&self.identity_discovery_cache, discovered_agent).await;

        // Record consent AFTER successful publish so heartbeats don't start
        // including user identity if this announcement never actually propagated.
        if include_user_identity && human_consent {
            self.user_identity_consented
                .store(true, std::sync::atomic::Ordering::Release);
        }

        Ok(())
    }

    /// Get all discovered agents from identity announcements.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn discovered_agents(&self) -> error::Result<Vec<DiscoveredAgent>> {
        self.start_identity_listener().await?;
        let cutoff = Self::unix_timestamp_secs().saturating_sub(self.identity_ttl_secs);
        let mut agents: Vec<_> = self
            .identity_discovery_cache
            .read()
            .await
            .values()
            .filter(|a| discovery_record_is_live(a.announced_at, a.last_seen, cutoff))
            .cloned()
            .collect();
        agents.sort_by_key(|a| a.agent_id.0);
        Ok(agents)
    }

    /// Get all currently-online agents from live presence beacons.
    ///
    /// This is the backing view for `/presence/online`: signed identity
    /// announcements provide the AgentId/MachineId binding, while presence
    /// beacons provide short-TTL liveness. Fresh identity-cache entries are
    /// included as a startup fallback before the first beacon poll converges.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn online_agents(&self) -> error::Result<Vec<DiscoveredAgent>> {
        self.start_identity_listener().await?;
        let cutoff = Self::unix_timestamp_secs().saturating_sub(self.identity_ttl_secs);
        let cache = self.identity_discovery_cache.read().await;
        let mut seen = std::collections::HashSet::new();
        let mut agents = Vec::new();

        for agent in cache
            .values()
            .filter(|agent| discovery_record_is_live(agent.announced_at, agent.last_seen, cutoff))
        {
            if seen.insert(agent.agent_id) {
                agents.push(agent.clone());
            }
        }

        if let Some(ref pw) = self.presence {
            let records = pw
                .manager()
                .get_group_presence(crate::presence::global_presence_topic())
                .await;
            for (peer_id, record) in records {
                if let Some(agent) =
                    crate::presence::presence_record_to_discovered_agent(peer_id, &record, &cache)
                {
                    if seen.insert(agent.agent_id) {
                        agents.push(agent);
                    }
                }
            }
        }

        agents.sort_by_key(|a| a.agent_id.0);
        Ok(agents)
    }

    /// Return all currently retained discovered agents, regardless of TTL.
    ///
    /// Unlike [`Self::discovered_agents`], this method skips read-time TTL
    /// filtering. After [`Self::join_network`] starts the background discovery
    /// cache reaper, stale entries may still be physically removed, so this is
    /// a retained-cache view rather than an "all agents ever seen" archive.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn discovered_agents_unfiltered(&self) -> error::Result<Vec<DiscoveredAgent>> {
        self.start_identity_listener().await?;
        let mut agents: Vec<_> = self
            .identity_discovery_cache
            .read()
            .await
            .values()
            .cloned()
            .collect();
        agents.sort_by_key(|a| a.agent_id.0);
        Ok(agents)
    }

    /// Get one discovered agent record by agent ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn discovered_agent(
        &self,
        agent_id: identity::AgentId,
    ) -> error::Result<Option<DiscoveredAgent>> {
        self.start_identity_listener().await?;
        Ok(self
            .identity_discovery_cache
            .read()
            .await
            .get(&agent_id)
            .cloned())
    }

    /// Get all discovered machine endpoints from machine announcements.
    ///
    /// The returned records are keyed by `machine_id`, which is the actual
    /// transport identity used for direct dials, hole-punching, and relay
    /// selection. Agent and user identities are link indexes over these
    /// machine records.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn discovered_machines(&self) -> error::Result<Vec<DiscoveredMachine>> {
        self.start_identity_listener().await?;
        let cutoff = Self::unix_timestamp_secs().saturating_sub(self.identity_ttl_secs);
        let mut machines: Vec<_> = self
            .machine_discovery_cache
            .read()
            .await
            .values()
            .filter(|m| discovery_record_is_live(m.announced_at, m.last_seen, cutoff))
            .cloned()
            .collect();
        machines.sort_by_key(|m| m.machine_id.0);
        Ok(machines)
    }

    /// Return all currently retained discovered machines, regardless of TTL.
    ///
    /// Unlike [`Self::discovered_machines`], this method skips read-time TTL
    /// filtering. After [`Self::join_network`] starts the background discovery
    /// cache reaper, stale entries may still be physically removed, so this is
    /// a retained-cache view rather than an "all machines ever seen" archive.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn discovered_machines_unfiltered(&self) -> error::Result<Vec<DiscoveredMachine>> {
        self.start_identity_listener().await?;
        let mut machines: Vec<_> = self
            .machine_discovery_cache
            .read()
            .await
            .values()
            .cloned()
            .collect();
        machines.sort_by_key(|m| m.machine_id.0);
        Ok(machines)
    }

    /// Get one discovered machine record by machine ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn discovered_machine(
        &self,
        machine_id: identity::MachineId,
    ) -> error::Result<Option<DiscoveredMachine>> {
        self.start_identity_listener().await?;
        Ok(self
            .machine_discovery_cache
            .read()
            .await
            .get(&machine_id)
            .cloned())
    }

    /// Resolve a known agent identity to its current machine endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn machine_for_agent(
        &self,
        agent_id: identity::AgentId,
    ) -> error::Result<Option<DiscoveredMachine>> {
        self.start_identity_listener().await?;
        let machine_id = {
            let agents = self.identity_discovery_cache.read().await;
            agents.get(&agent_id).map(|agent| agent.machine_id)
        };
        let Some(machine_id) = machine_id else {
            return Ok(None);
        };
        Ok(self
            .machine_discovery_cache
            .read()
            .await
            .get(&machine_id)
            .cloned())
    }

    /// Find all machine endpoints linked to a consented user identity.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn find_machines_by_user(
        &self,
        user_id: identity::UserId,
    ) -> error::Result<Vec<DiscoveredMachine>> {
        self.start_identity_listener().await?;
        let cutoff = Self::unix_timestamp_secs().saturating_sub(self.identity_ttl_secs);
        let mut machines: Vec<_> = self
            .machine_discovery_cache
            .read()
            .await
            .values()
            .filter(|m| {
                discovery_record_is_live(m.announced_at, m.last_seen, cutoff)
                    && m.user_ids.contains(&user_id)
            })
            .cloned()
            .collect();
        machines.sort_by_key(|m| m.machine_id.0);
        Ok(machines)
    }

    /// Publish a signed [`UserAnnouncement`] for this agent's user identity.
    ///
    /// Builds the roster from the agent certificates the user has issued for
    /// every agent visible through this `Agent` — at minimum, this agent's
    /// own certificate. Requires explicit human consent to avoid an unwary
    /// caller broadcasting user identity.
    ///
    /// # Errors
    ///
    /// Returns an error if no user keypair is configured, `human_consent` is
    /// false, no agent certificate is available, signing fails, or the
    /// gossip runtime is not initialised.
    pub async fn announce_user_identity(&self, human_consent: bool) -> error::Result<()> {
        if !human_consent {
            return Err(error::IdentityError::Storage(std::io::Error::other(
                "user announcement requires explicit human consent — set human_consent: true",
            )));
        }
        let user_kp = self.identity.user_keypair().ok_or_else(|| {
            error::IdentityError::Storage(std::io::Error::other(
                "user announcement requested but no user identity is configured",
            ))
        })?;
        let own_cert = self.identity.agent_certificate().cloned().ok_or_else(|| {
            error::IdentityError::Storage(std::io::Error::other(
                "user announcement requested but agent certificate is missing",
            ))
        })?;
        let runtime = self.gossip_runtime.as_ref().ok_or_else(|| {
            error::IdentityError::Storage(std::io::Error::other(
                "gossip runtime not initialized - configure agent with network first",
            ))
        })?;
        self.start_identity_listener().await?;

        let announced_at = Self::unix_timestamp_secs();
        let announcement = UserAnnouncement::sign(user_kp, vec![own_cert], announced_at)?;
        let payload = bytes::Bytes::from(bincode::serialize(&announcement).map_err(|e| {
            error::IdentityError::Serialization(format!(
                "failed to serialize user announcement: {e}"
            ))
        })?);
        runtime
            .pubsub()
            .publish(shard_topic_for_user(&announcement.user_id), payload.clone())
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "failed to publish user announcement to shard topic: {e}"
                )))
            })?;
        runtime
            .pubsub()
            .publish(USER_ANNOUNCE_TOPIC.to_string(), payload)
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "failed to publish user announcement: {e}"
                )))
            })?;

        let now = Self::unix_timestamp_secs();
        let incoming = DiscoveredUser::from_announcement(&announcement, now);
        self.user_discovery_cache
            .write()
            .await
            .insert(incoming.user_id, incoming);
        Ok(())
    }

    /// Get a discovered user by ID.
    ///
    /// Returns `Ok(None)` if the user has never announced or the cached
    /// entry is older than `identity_ttl_secs`.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn discovered_user(
        &self,
        user_id: identity::UserId,
    ) -> error::Result<Option<DiscoveredUser>> {
        self.start_identity_listener().await?;
        let cutoff = Self::unix_timestamp_secs().saturating_sub(self.identity_ttl_secs);
        Ok(self
            .user_discovery_cache
            .read()
            .await
            .get(&user_id)
            .filter(|u| discovery_record_is_live(u.announced_at, u.last_seen, cutoff))
            .cloned())
    }

    /// List all currently-discovered users (those with a fresh announcement).
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn discovered_users(&self) -> error::Result<Vec<DiscoveredUser>> {
        self.start_identity_listener().await?;
        let cutoff = Self::unix_timestamp_secs().saturating_sub(self.identity_ttl_secs);
        let mut users: Vec<_> = self
            .user_discovery_cache
            .read()
            .await
            .values()
            .filter(|u| discovery_record_is_live(u.announced_at, u.last_seen, cutoff))
            .cloned()
            .collect();
        users.sort_by_key(|u| u.user_id.0);
        Ok(users)
    }

    /// Return the current retained entry counts for the three discovery caches.
    ///
    /// Primarily intended for diagnostics and soak monitoring. The reaper
    /// (started by `join_network`) keeps these bounded by physically removing
    /// stale entries; without the reaper the counts grow monotonically with
    /// every unique agent/machine/user ever observed.
    #[must_use]
    pub async fn discovery_cache_entry_counts(&self) -> (usize, usize, usize) {
        let id = self.identity_discovery_cache.read().await.len();
        let mach = self.machine_discovery_cache.read().await.len();
        let usr = self.user_discovery_cache.read().await.len();
        (id, mach, usr)
    }

    async fn start_identity_listener(&self) -> error::Result<()> {
        let runtime = self.gossip_runtime.as_ref().ok_or_else(|| {
            error::IdentityError::Storage(std::io::Error::other(
                "gossip runtime not initialized - configure agent with network first",
            ))
        })?;

        if self
            .identity_listener_started
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return Ok(());
        }

        let mut sub_legacy = runtime
            .pubsub()
            .subscribe(IDENTITY_ANNOUNCE_TOPIC.to_string())
            .await;
        let own_shard_topic = shard_topic_for_agent(&self.agent_id());
        let mut sub_shard = runtime.pubsub().subscribe(own_shard_topic).await;
        let mut sub_machine_legacy = runtime
            .pubsub()
            .subscribe(MACHINE_ANNOUNCE_TOPIC.to_string())
            .await;
        let own_machine_shard_topic = shard_topic_for_machine(&self.machine_id());
        let mut sub_machine_shard = runtime.pubsub().subscribe(own_machine_shard_topic).await;
        let mut sub_user_legacy = runtime
            .pubsub()
            .subscribe(USER_ANNOUNCE_TOPIC.to_string())
            .await;
        // Subscribe to our own user's shard (if we have a user identity) so
        // we receive announcements addressed to us as well as broadcasts.
        let mut sub_user_shard = match self.user_id() {
            Some(uid) => Some(runtime.pubsub().subscribe(shard_topic_for_user(&uid)).await),
            None => None,
        };
        let cache = std::sync::Arc::clone(&self.identity_discovery_cache);
        let machine_cache = std::sync::Arc::clone(&self.machine_discovery_cache);
        let user_cache = std::sync::Arc::clone(&self.user_discovery_cache);
        let bootstrap_cache = self.bootstrap_cache.clone();
        let contact_store = std::sync::Arc::clone(&self.contact_store);
        let direct_messaging = std::sync::Arc::clone(&self.direct_messaging);
        let network = self.network.as_ref().map(std::sync::Arc::clone);
        let allow_local_scope = network
            .as_ref()
            .is_some_and(|network| allow_local_discovery_addresses(network.config()));
        let own_agent_id = self.agent_id();
        let own_machine_id = self.machine_id();
        let own_user_id = self.user_id();
        let rebroadcast_pubsub = std::sync::Arc::clone(runtime.pubsub());
        let token = self.shutdown_token.clone();
        // Subscribe to revocation records so they are applied on receipt.
        let mut sub_revocation = runtime
            .pubsub()
            .subscribe(REVOCATION_TOPIC.to_string())
            .await;
        let revocation_set = std::sync::Arc::clone(&self.revocation_set);
        let identity_dir_for_listener = self.identity_dir.clone();
        let contact_store_for_evict = std::sync::Arc::clone(&self.contact_store);

        self.spawn_tracked(async move {
            enum DiscoveryMessage {
                Identity(crate::gossip::PubSubMessage),
                Machine(crate::gossip::PubSubMessage),
                User(crate::gossip::PubSubMessage),
                Revocation(crate::gossip::PubSubMessage),
            }

            // Track agents we've already initiated auto-connect to, preventing
            // duplicate connection attempts from concurrent announcements.
            let mut auto_connect_attempted = std::collections::HashSet::<identity::AgentId>::new();

            // One-shot dedup for re-broadcast: (agent_id, announced_at)
            // → first-rebroadcast Instant. Bounds each fresh announcement to at
            // most one receiver-side re-publish per daemon. Repeating the same
            // payload every few seconds forms a PubSub feedback loop on the
            // bootstrap mesh and delays latency-sensitive user messages.
            let mut rebroadcast_state: std::collections::HashMap<
                (identity::AgentId, u64),
                std::time::Instant,
            > = std::collections::HashMap::new();
            let mut machine_rebroadcast_state: std::collections::HashMap<
                (identity::MachineId, u64),
                std::time::Instant,
            > = std::collections::HashMap::new();
            let mut seen_identity_payloads: std::collections::HashMap<
                blake3::Hash,
                std::time::Instant,
            > = std::collections::HashMap::new();
            let mut seen_machine_payloads: std::collections::HashMap<
                blake3::Hash,
                std::time::Instant,
            > = std::collections::HashMap::new();
            let mut user_rebroadcast_state: std::collections::HashMap<
                (identity::UserId, u64),
                std::time::Instant,
            > = std::collections::HashMap::new();
            const VERIFIED_PAYLOAD_TTL: std::time::Duration = std::time::Duration::from_secs(60);

            let has_recent_verified_payload =
                |seen: &std::collections::HashMap<blake3::Hash, std::time::Instant>,
                 payload: &[u8]| {
                    let key = blake3::hash(payload);
                    matches!(seen.get(&key), Some(last) if last.elapsed() < VERIFIED_PAYLOAD_TTL)
                };
            let remember_verified_payload =
                |seen: &mut std::collections::HashMap<blake3::Hash, std::time::Instant>,
                 payload: &[u8]| {
                    let now = std::time::Instant::now();
                    seen.insert(blake3::hash(payload), now);
                    if seen.len() > 4096 {
                        let cutoff = now - VERIFIED_PAYLOAD_TTL;
                        seen.retain(|_, t| *t >= cutoff);
                    }
                };

            loop {
                // Drain whichever subscription fires next; deduplicate by ID in cache.
                // The user-shard subscription is conditional on having a local
                // user identity; when absent, that arm yields a pending future
                // so select! skips it cleanly.
                let msg = tokio::select! {
                    Some(m) = sub_legacy.recv() => DiscoveryMessage::Identity(m),
                    Some(m) = sub_shard.recv() => DiscoveryMessage::Identity(m),
                    Some(m) = sub_machine_legacy.recv() => DiscoveryMessage::Machine(m),
                    Some(m) = sub_machine_shard.recv() => DiscoveryMessage::Machine(m),
                    Some(m) = sub_user_legacy.recv() => DiscoveryMessage::User(m),
                    Some(m) = async {
                        match sub_user_shard.as_mut() {
                            Some(s) => s.recv().await,
                            None => std::future::pending().await,
                        }
                    } => DiscoveryMessage::User(m),
                    Some(m) = sub_revocation.recv() => DiscoveryMessage::Revocation(m),
                    // Required for PROMPT shutdown: without this arm the listener
                    // only exits when every gossip subscription closes (the
                    // `else => break` path), forcing shutdown() to wait out its
                    // 3s grace-then-abort window. Cancelling the token here lets
                    // it break immediately. Adding this always-eligible-on-cancel
                    // branch only shifts tokio::select!'s pseudo-random tie-break
                    // distribution among the recv arms — behaviorally inert here
                    // because each per-topic message is handled independently
                    // with no cross-topic ordering guarantee.
                    _ = token.cancelled() => break,
                    else => break,
                };
                let msg = match msg {
                    DiscoveryMessage::Machine(msg) => {
                        let raw_payload = msg.payload.clone();
                        let already_verified =
                            has_recent_verified_payload(&seen_machine_payloads, &raw_payload);
                        let announcement = match deserialize_machine_announcement(&raw_payload) {
                            Ok(a) => a,
                            Err(e) => {
                                tracing::debug!(
                                    "Ignoring invalid machine announcement payload: {}",
                                    e
                                );
                                continue;
                            }
                        };

                        if !already_verified {
                            if let Err(e) = announcement.verify() {
                                tracing::warn!("Ignoring unverifiable machine announcement: {}", e);
                                continue;
                            }
                            remember_verified_payload(&mut seen_machine_payloads, &raw_payload);
                        }

                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |d| d.as_secs());

                        let bootstrap_addresses = filter_publicly_advertisable_addrs(
                            announcement.addresses.iter().copied(),
                        );
                        if !bootstrap_addresses.is_empty() {
                            if let Some(ref bc) = &bootstrap_cache {
                                let peer_id = ant_quic::PeerId(announcement.machine_id.0);
                                bc.add_from_connection(peer_id, bootstrap_addresses.clone(), None)
                                    .await;
                            }
                        }

                        let discovery_addresses = filter_discovery_announcement_addrs(
                            announcement.addresses.iter().copied(),
                            allow_local_scope,
                        );
                        let filtered_addr_count = discovery_addresses.len();
                        upsert_discovered_machine(
                            &machine_cache,
                            DiscoveredMachine::from_machine_announcement(
                                &announcement,
                                discovery_addresses,
                                now,
                            ),
                        )
                        .await;
                        tracing::debug!(
                            target: "x0x::discovery",
                            announcement_kind = "machine_received",
                            machine_prefix = %network::hex_prefix(&announcement.machine_id.0, 4),
                            addr_total = announcement.addresses.len(),
                            filtered_addr_count,
                            nat_type = announcement.nat_type.as_deref().unwrap_or("unknown"),
                            can_receive_direct = ?announcement.can_receive_direct,
                            relay_capable = ?announcement.is_relay,
                            coordinator_capable = ?announcement.is_coordinator,
                            "cached verified machine announcement"
                        );

                        if announcement.machine_id != own_machine_id {
                            let key = (announcement.machine_id, announcement.announced_at);
                            if should_rebroadcast_discovery_once(
                                &mut machine_rebroadcast_state,
                                key,
                                std::time::Instant::now(),
                            ) {
                                let pubsub = std::sync::Arc::clone(&rebroadcast_pubsub);
                                tokio::spawn(async move {
                                    if let Err(e) = pubsub
                                        .publish(MACHINE_ANNOUNCE_TOPIC.to_string(), raw_payload)
                                        .await
                                    {
                                        tracing::debug!(
                                            "machine announcement re-broadcast failed: {e}"
                                        );
                                    }
                                });
                            }
                        }
                        continue;
                    }
                    DiscoveryMessage::User(msg) => {
                        let raw_payload = msg.payload.clone();
                        let announcement = match deserialize_user_announcement(&raw_payload) {
                            Ok(a) => a,
                            Err(e) => {
                                tracing::debug!(
                                    "Ignoring invalid user announcement payload: {}",
                                    e
                                );
                                continue;
                            }
                        };
                        if let Err(e) = announcement.verify() {
                            tracing::warn!("Ignoring unverifiable user announcement: {}", e);
                            continue;
                        }
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |d| d.as_secs());
                        let incoming = DiscoveredUser::from_announcement(&announcement, now);
                        {
                            let mut cache = user_cache.write().await;
                            match cache.get_mut(&incoming.user_id) {
                                Some(existing) if incoming.announced_at < existing.announced_at => {
                                    // Ignore stale announcement.
                                }
                                Some(existing) => {
                                    existing.user_public_key = incoming.user_public_key;
                                    existing.agent_certificates = incoming.agent_certificates;
                                    existing.agent_ids = incoming.agent_ids;
                                    existing.announced_at = incoming.announced_at;
                                    existing.last_seen = now;
                                }
                                None => {
                                    cache.insert(incoming.user_id, incoming);
                                }
                            }
                        }
                        tracing::debug!(
                            target: "x0x::discovery",
                            announcement_kind = "user_received",
                            user_prefix = %network::hex_prefix(&announcement.user_id.0, 4),
                            agent_count = announcement.agent_certificates.len(),
                            "cached verified user announcement"
                        );
                        // Rebroadcast non-self announcements once, matching
                        // identity / machine announcements.
                        if Some(announcement.user_id) != own_user_id {
                            let key = (announcement.user_id, announcement.announced_at);
                            if should_rebroadcast_discovery_once(
                                &mut user_rebroadcast_state,
                                key,
                                std::time::Instant::now(),
                            ) {
                                let pubsub = std::sync::Arc::clone(&rebroadcast_pubsub);
                                tokio::spawn(async move {
                                    if let Err(e) = pubsub
                                        .publish(USER_ANNOUNCE_TOPIC.to_string(), raw_payload)
                                        .await
                                    {
                                        tracing::debug!(
                                            "user announcement re-broadcast failed: {e}"
                                        );
                                    }
                                });
                            }
                        }
                        continue;
                    }
                    DiscoveryMessage::Identity(msg) => msg,
                    DiscoveryMessage::Revocation(msg) => {
                        // Size-limit: max 2 MiB for a revocation batch (records
                        // are ~5.3 KB each; 2 MiB ≈ 380 records, far beyond
                        // any realistic fleet size in v1).
                        const MAX_REVOCATION_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
                        if msg.payload.len() > MAX_REVOCATION_PAYLOAD_BYTES {
                            tracing::debug!(
                                "ignoring oversized revocation payload ({} bytes)",
                                msg.payload.len()
                            );
                            continue;
                        }
                        let records: Vec<revocation::RevocationRecord> =
                            match bincode::deserialize(&msg.payload) {
                                Ok(r) => r,
                                Err(e) => {
                                    tracing::debug!("ignoring invalid revocation payload: {e}");
                                    continue;
                                }
                            };
                        let mut newly_inserted = Vec::new();
                        // Resolve subject certificates from the discovery cache
                        // so gossiped issuer-revocations (a user un-vouching a
                        // certified agent) can be authority-verified on receipt
                        // (issue #191). `verify_authority` for an issuer-
                        // revocation requires the subject cert; self/machine
                        // revocations need none. A cert not in the local cache
                        // means the issuer-revocation is rejected fail-closed
                        // — the cert must have been announced first (EP1).
                        // Built before taking the revocation-set write lock so
                        // no two identity locks are held at once.
                        let subject_certs = collect_subject_certs(&*cache.read().await);
                        {
                            let mut set = revocation_set.write().await;
                            for record in records {
                                if set.contains_hash(&record.record_hash()) {
                                    continue; // already known — skip re-verification
                                }
                                let subject_cert = match &record.subject {
                                    revocation::RevokedSubject::Agent(agent_id) => {
                                        subject_certs.get(agent_id)
                                    }
                                    _ => None,
                                };
                                match set.verify_and_insert(record.clone(), subject_cert) {
                                    Ok(true) => newly_inserted.push(record),
                                    Ok(false) => {} // dup
                                    Err(e) => {
                                        tracing::debug!(
                                            "revocation record rejected: {e}"
                                        );
                                    }
                                }
                            }
                        }
                        if !newly_inserted.is_empty() {
                            // Persist asynchronously — best-effort; if it fails
                            // the revocation is still enforced in memory for this
                            // run. Snapshot the live set's encoded bytes under a
                            // brief read lock (issuer-revocations carry their
                            // authorizing cert in PersistedRevocation, which the
                            // encoder preserves); the disk write runs off-lock.
                            // The previous rebuild re-inserted records with
                            // `None` cert, silently dropping every issuer-
                            // revocation on save (issue #191).
                            let persisted_bytes = revocation_set.read().await.to_bytes();
                            let id_dir = identity_dir_for_listener.clone();
                            tokio::spawn(async move {
                                match persisted_bytes {
                                    Ok(bytes) => {
                                        if let Err(e) = storage::save_revocation_set_bytes(
                                            bytes,
                                            id_dir.as_deref(),
                                        )
                                        .await
                                        {
                                            tracing::warn!(
                                                "failed to persist revocation set: {e}"
                                            );
                                        }
                                    }
                                    Err(e) => tracing::warn!(
                                        "failed to encode revocation set for persistence: {e}"
                                    ),
                                }
                            });
                            // Evict revoked subjects from discovery caches.
                            for record in newly_inserted {
                                match &record.subject {
                                    revocation::RevokedSubject::Agent(agent_id) => {
                                        if let Some(entry) = cache.write().await.remove(agent_id) {
                                            machine_cache.write().await.remove(&entry.machine_id);
                                        }
                                        let mut cs = contact_store_for_evict.write().await;
                                        cs.set_trust(agent_id, contacts::TrustLevel::Blocked);
                                        tracing::info!(
                                            agent = %hex::encode(agent_id.as_bytes()),
                                            "evicted revoked agent (received via gossip)"
                                        );
                                    }
                                    revocation::RevokedSubject::Machine(machine_id) => {
                                        machine_cache.write().await.remove(machine_id);
                                        cache.write().await.retain(|_, a| a.machine_id != *machine_id);
                                        tracing::info!(
                                            machine = %hex::encode(machine_id.as_bytes()),
                                            "evicted revoked machine (received via gossip)"
                                        );
                                    }
                                }
                            }
                        }
                        continue;
                    }
                };
                let raw_payload = msg.payload.clone();
                let already_verified =
                    has_recent_verified_payload(&seen_identity_payloads, &raw_payload);
                let announcement = match deserialize_identity_announcement(&raw_payload) {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::debug!("Ignoring invalid identity announcement payload: {}", e);
                        continue;
                    }
                };

                if !already_verified {
                    if let Err(e) = announcement.verify() {
                        tracing::warn!("Ignoring unverifiable identity announcement: {}", e);
                        continue;
                    }
                    remember_verified_payload(&mut seen_identity_payloads, &raw_payload);
                }

                // Evaluate trust for this (agent, machine) pair.
                // Blocked or machine-pinning violations are silently dropped.
                {
                    let store = contact_store.read().await;
                    let evaluator = trust::TrustEvaluator::new(&store);
                    let decision = evaluator.evaluate(&trust::TrustContext {
                        agent_id: &announcement.agent_id,
                        machine_id: &announcement.machine_id,
                    });
                    match decision {
                        trust::TrustDecision::RejectBlocked => {
                            tracing::debug!(
                                "Dropping identity announcement from blocked agent {:?}",
                                hex::encode(&announcement.agent_id.0[..8]),
                            );
                            continue;
                        }
                        trust::TrustDecision::RejectMachineMismatch => {
                            tracing::warn!(
                                "Dropping identity announcement from agent {}: machine {} not in pinned list",
                                crate::logging::LogAgentId::from(&announcement.agent_id),
                                crate::logging::LogMachineId::from(&announcement.machine_id),
                            );
                            continue;
                        }
                        _ => {}
                    }
                }

                // Enforcement point 1 — revocation gate.
                // Fail-closed: a revoked agent or machine is silently dropped
                // even if the trust store says otherwise.  This check must come
                // BEFORE inserting into the discovery cache so a revoked peer
                // never gets a `verified` annotation.
                {
                    let revoked = revocation_set.read().await;
                    if revoked.is_agent_revoked(&announcement.agent_id) {
                        tracing::debug!(
                            "Dropping identity announcement from revoked agent {:?}",
                            hex::encode(&announcement.agent_id.0[..8]),
                        );
                        continue;
                    }
                    if revoked.is_machine_revoked(&announcement.machine_id) {
                        tracing::debug!(
                            "Dropping identity announcement from revoked machine {:?}",
                            hex::encode(&announcement.machine_id.0[..8]),
                        );
                        continue;
                    }
                }

                // Enforcement point 1b — cert expiry gate.
                // Drop announcements whose embedded cert is expired (fail-closed).
                // Announcements without a cert (cert == None) are fail-open:
                // they just won't carry a user binding and cert_not_after will be None.
                if let Some(cert) = &announcement.agent_certificate {
                    if identity::is_expired(cert.not_after(), Agent::unix_timestamp_secs()) {
                        tracing::debug!(
                            "Dropping identity announcement with expired cert from agent {:?}",
                            hex::encode(&announcement.agent_id.0[..8]),
                        );
                        continue;
                    }
                }

                // Update machine records in the contact store.
                //
                // The daemon never registers its own agent as a contact: a self
                // entry would be noise on the `/contacts` projection and pollute
                // contact-set assertions (issue #145). The rebroadcast and
                // auto-connect branches below already self-skip on
                // `announcement.agent_id != own_agent_id`; the machine-record
                // upsert was the sole outlier. Foreign observation still
                // registers normally.
                register_announced_machine(
                    &contact_store,
                    own_agent_id,
                    announcement.agent_id,
                    announcement.machine_id,
                )
                .await;

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());

                // Add only globally-advertisable addresses to the persistent
                // bootstrap cache. Legacy peers may still ship LAN, CGNAT,
                // loopback, or port-zero entries, but those are not useful
                // outside link-local discovery and must not become dial
                // candidates for globally propagated announcements.
                let bootstrap_addresses =
                    filter_publicly_advertisable_addrs(announcement.addresses.iter().copied());
                let discovery_addresses = filter_discovery_announcement_addrs(
                    announcement.addresses.iter().copied(),
                    allow_local_scope,
                );
                let filtered_addr_count = discovery_addresses.len();
                let auto_connect_addresses = discovery_addresses.clone();
                {
                    if !bootstrap_addresses.is_empty() {
                        if let Some(ref bc) = &bootstrap_cache {
                            let peer_id = ant_quic::PeerId(announcement.machine_id.0);
                            bc.add_from_connection(peer_id, bootstrap_addresses.clone(), None)
                                .await;
                            tracing::debug!(
                                "Added {} public addresses to bootstrap cache for agent {:?} (machine {:?})",
                                bootstrap_addresses.len(),
                                announcement.agent_id,
                                hex::encode(&announcement.machine_id.0[..8]),
                            );
                        }
                    }
                }

                // Cache public addresses on global partitions, but keep
                // LAN/loopback hints on explicit local/testnet partitions.
                // Empty address lists are preserved (the `AlreadyConnected`
                // path in `connect_to_agent` handles gossip peers we only reach
                // by an existing QUIC connection).
                let cert_not_after = announcement
                    .agent_certificate
                    .as_ref()
                    .and_then(|c| c.not_after());
                let discovered_agent = DiscoveredAgent {
                    agent_id: announcement.agent_id,
                    machine_id: announcement.machine_id,
                    user_id: announcement.user_id,
                    addresses: discovery_addresses,
                    announced_at: announcement.announced_at,
                    last_seen: now,
                    machine_public_key: announcement.machine_public_key.clone(),
                    nat_type: announcement.nat_type.clone(),
                    can_receive_direct: announcement.can_receive_direct,
                    is_relay: announcement.is_relay,
                    is_coordinator: announcement.is_coordinator,
                    reachable_via: announcement.reachable_via.clone(),
                    relay_candidates: announcement.relay_candidates.clone(),
                    cert_not_after,
                    agent_certificate: announcement.agent_certificate.clone(),
                };
                upsert_discovered_machine_from_agent(&machine_cache, &discovered_agent).await;
                upsert_discovered_agent(&cache, discovered_agent).await;
                tracing::debug!(
                    target: "x0x::discovery",
                    announcement_kind = "received",
                    agent_prefix = %network::hex_prefix(&announcement.agent_id.0, 4),
                    machine_prefix = %network::hex_prefix(&announcement.machine_id.0, 4),
                    addr_total = announcement.addresses.len(),
                    filtered_addr_count,
                    nat_type = announcement.nat_type.as_deref().unwrap_or("unknown"),
                    can_receive_direct = ?announcement.can_receive_direct,
                    relay_capable = ?announcement.is_relay,
                    coordinator_capable = ?announcement.is_coordinator,
                    reachable_via_count = announcement.reachable_via.len(),
                    relay_candidate_count = announcement.relay_candidates.len(),
                    "cached verified identity announcement"
                );

                // Identity announcements are the strongest agent↔machine binding we have.
                // Register the mapping immediately so reverse direct-send can resolve the
                // machine even before the first inbound direct payload arrives.
                direct_messaging
                    .register_agent(announcement.agent_id, announcement.machine_id)
                    .await;

                // Epidemic re-broadcast — mirrors the release-manifest
                // re-broadcast pattern. Bootstrap-node meshes have patchy
                // PlumTree overlap for the identity-announce topic: the
                // origin's tree only reaches 1–2 hops reliably. Making
                // every verified recipient re-publish guarantees flood
                // convergence across the mesh. One-shot dedup on
                // (agent_id, announced_at) bounds amplification. Pub/Sub
                // v2 re-signs each publish with a new message ID so
                // PlumTree's own dedup cannot suppress repeated forwards;
                // therefore each daemon forwards a given announcement at most
                // once.
                if announcement.agent_id != own_agent_id {
                    let key = (announcement.agent_id, announcement.announced_at);
                    if should_rebroadcast_discovery_once(
                        &mut rebroadcast_state,
                        key,
                        std::time::Instant::now(),
                    ) {
                        let pubsub = std::sync::Arc::clone(&rebroadcast_pubsub);
                        let payload = raw_payload.clone();
                        tokio::spawn(async move {
                            if let Err(e) = pubsub
                                .publish(IDENTITY_ANNOUNCE_TOPIC.to_string(), payload)
                                .await
                            {
                                tracing::debug!("identity announcement re-broadcast failed: {e}");
                            }
                        });
                    }
                }

                // Reconcile the agent-level direct-message registry if the transport peer
                // is already connected (for example an inbound accept that happened before
                // this announcement reached us).
                if let Some(ref net) = &network {
                    let ant_peer_id = ant_quic::PeerId(announcement.machine_id.0);
                    if net.is_connected(&ant_peer_id).await {
                        direct_messaging
                            .mark_connected(announcement.agent_id, announcement.machine_id)
                            .await;
                    }
                }

                // Auto-connect to discovered agents so pub/sub messages can route
                // between peers that share bootstrap nodes but aren't directly connected.
                // The gossip topology refresh (every 1s) will add the new peer to
                // PlumTree topic trees once the QUIC connection is established.
                if announcement.agent_id != own_agent_id
                    && !auto_connect_addresses.is_empty()
                    && !auto_connect_attempted.contains(&announcement.agent_id)
                {
                    if let Some(ref net) = &network {
                        let ant_peer = ant_quic::PeerId(announcement.machine_id.0);
                        if !net.is_connected(&ant_peer).await {
                            auto_connect_attempted.insert(announcement.agent_id);
                            let net = std::sync::Arc::clone(net);
                            let addresses = auto_connect_addresses.clone();
                            tokio::spawn(async move {
                                for addr in &addresses {
                                    match net.connect_addr(*addr).await {
                                        Ok(_) => {
                                            tracing::info!(
                                                "Auto-connected to discovered agent at {addr}",
                                            );
                                            return;
                                        }
                                        Err(e) => {
                                            tracing::debug!("Auto-connect to {addr} failed: {e}",);
                                        }
                                    }
                                }
                                tracing::debug!(
                                    "Auto-connect exhausted all {} addresses for discovered agent",
                                    addresses.len(),
                                );
                            });
                        }
                    }
                }
            }
        });

        Ok(())
    }

    fn unix_timestamp_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn announcement_addresses(&self) -> Vec<std::net::SocketAddr> {
        match self.network.as_ref().and_then(|n| n.local_addr()) {
            Some(addr) if addr.port() > 0 => filter_discovery_announcement_addrs(
                collect_local_interface_addrs(addr.port()),
                self.network
                    .as_ref()
                    .is_some_and(|network| allow_local_discovery_addresses(network.config())),
            ),
            _ => Vec::new(),
        }
    }

    fn build_identity_announcement(
        &self,
        include_user_identity: bool,
        human_consent: bool,
    ) -> error::Result<IdentityAnnouncement> {
        self.build_identity_announcement_with_addrs(IdentityAnnouncementBuildOptions {
            include_user_identity,
            human_consent,
            addresses: self.announcement_addresses(),
            assist_snapshot: None,
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
            allow_local_scope: false,
        })
    }

    fn build_identity_announcement_with_addrs(
        &self,
        options: IdentityAnnouncementBuildOptions<'_>,
    ) -> error::Result<IdentityAnnouncement> {
        let IdentityAnnouncementBuildOptions {
            include_user_identity,
            human_consent,
            addresses,
            assist_snapshot,
            reachable_via,
            relay_candidates,
            allow_local_scope,
        } = options;
        if include_user_identity && !human_consent {
            return Err(error::IdentityError::Storage(std::io::Error::other(
                "human identity disclosure requires explicit human consent — set human_consent: true in the request body",
            )));
        }
        let addresses = filter_discovery_announcement_addrs(addresses, allow_local_scope);

        let (user_id, agent_certificate) = if include_user_identity {
            let user_id = self.user_id().ok_or_else(|| {
                error::IdentityError::Storage(std::io::Error::other(
                    "human identity disclosure requested but no user identity is configured — set user_key_path in your config.toml to point at your user keypair file",
                ))
            })?;
            let cert = self.agent_certificate().cloned().ok_or_else(|| {
                error::IdentityError::Storage(std::io::Error::other(
                    "human identity disclosure requested but agent certificate is missing",
                ))
            })?;
            (Some(user_id), Some(cert))
        } else {
            (None, None)
        };

        let machine_public_key = self
            .identity
            .machine_keypair()
            .public_key()
            .as_bytes()
            .to_vec();

        let unsigned = IdentityAnnouncementUnsigned {
            agent_id: self.agent_id(),
            machine_id: self.machine_id(),
            user_id,
            agent_certificate: agent_certificate.clone(),
            machine_public_key: machine_public_key.clone(),
            addresses,
            announced_at: Self::unix_timestamp_secs(),
            nat_type: assist_snapshot.and_then(|snapshot| snapshot.nat_type.clone()),
            can_receive_direct: assist_snapshot.and_then(|snapshot| snapshot.can_receive_direct),
            is_relay: assist_snapshot.and_then(|snapshot| snapshot.relay_capable),
            is_coordinator: assist_snapshot.and_then(|snapshot| snapshot.coordinator_capable),
            reachable_via,
            relay_candidates,
        };
        let unsigned_bytes = bincode::serialize(&unsigned).map_err(|e| {
            error::IdentityError::Serialization(format!(
                "failed to serialize unsigned identity announcement: {e}"
            ))
        })?;
        let machine_signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            self.identity.machine_keypair().secret_key(),
            &unsigned_bytes,
        )
        .map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!(
                "failed to sign identity announcement with machine key: {:?}",
                e
            )))
        })?
        .as_bytes()
        .to_vec();

        Ok(IdentityAnnouncement {
            agent_id: unsigned.agent_id,
            machine_id: unsigned.machine_id,
            user_id: unsigned.user_id,
            agent_certificate: unsigned.agent_certificate,
            machine_public_key,
            machine_signature,
            addresses: unsigned.addresses,
            announced_at: unsigned.announced_at,
            nat_type: unsigned.nat_type,
            can_receive_direct: unsigned.can_receive_direct,
            is_relay: unsigned.is_relay,
            is_coordinator: unsigned.is_coordinator,
            reachable_via: unsigned.reachable_via,
            relay_candidates: unsigned.relay_candidates,
        })
    }

    /// Join the x0x gossip network.
    ///
    /// Connects to bootstrap peers in parallel with automatic retries.
    /// Failed connections are retried after a delay to allow stale
    /// connections on remote nodes to expire.
    ///
    /// If the agent was not configured with a network, this method
    /// succeeds gracefully (nothing to join).
    pub async fn join_network(&self) -> error::Result<()> {
        let Some(network) = self.network.as_ref() else {
            tracing::debug!("join_network called but no network configured");
            return Ok(());
        };

        if let Some(ref runtime) = self.gossip_runtime {
            runtime.start().await.map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "failed to start gossip runtime: {e}"
                )))
            })?;
            tracing::info!("Gossip runtime started");
        }
        // Race guard (issue #116): if shutdown() already fired (token cancelled),
        // do not start the listeners. Combined with spawn_tracked's closed-check,
        // a shutdown that races mid-bootstrap cannot leave a listener running.
        if self.shutdown_token.is_cancelled() {
            tracing::info!("join_network aborted: shutdown already in progress");
            return Ok(());
        }
        self.start_identity_listener().await?;
        self.start_network_event_listener();
        self.start_direct_listener();
        self.start_stream_accept_loop();

        let bootstrap_nodes = network.config().bootstrap_nodes.clone();

        let min_connected = 3;
        let mut all_connected: Vec<std::net::SocketAddr> = Vec::new();

        // ant-quic now owns first-party mDNS discovery and auto-connect.
        // x0x keeps bootstrap/cache orchestration here, while the transport
        // layer handles zero-config LAN discovery internally.

        // Phase 0: Try quality-scored coordinator peers from bootstrap cache.
        // The bootstrap cache learns about coordinator-capable peers passively
        // through normal connections — no coordinator gossip topic needed.
        if let Some(ref cache) = self.bootstrap_cache {
            let coordinators = cache.select_coordinators(6).await;
            let coordinator_addrs: Vec<std::net::SocketAddr> = coordinators
                .iter()
                .flat_map(|peer| peer.preferred_addresses())
                .collect();

            if !coordinator_addrs.is_empty() {
                tracing::info!(
                    "Phase 0: Trying {} addresses from {} cached coordinators",
                    coordinator_addrs.len(),
                    coordinators.len()
                );
                let (succeeded, _failed) = self
                    .connect_peers_parallel_tracked(network, &coordinator_addrs)
                    .await;
                all_connected.extend(&succeeded);
                tracing::info!(
                    "Phase 0: {}/{} coordinator addresses connected",
                    succeeded.len(),
                    coordinator_addrs.len()
                );
            }
        }

        // Phase 1: Try cached peers first using the real ant-quic peer IDs.
        if all_connected.len() < min_connected {
            if let Some(ref cache) = self.bootstrap_cache {
                const PHASE1_PEER_CANDIDATES: usize = 12;
                let cached_peers = cache.select_peers(PHASE1_PEER_CANDIDATES).await;
                if !cached_peers.is_empty() {
                    tracing::info!("Phase 1: Trying {} cached peers", cached_peers.len());
                    let (succeeded, _failed) = self
                        .connect_cached_peers_parallel_tracked(network, &cached_peers)
                        .await;
                    all_connected.extend(&succeeded);
                    tracing::info!(
                        "Phase 1: {}/{} cached peers connected",
                        succeeded.len(),
                        cached_peers.len()
                    );
                }
            }
        } // end Phase 1 min_connected check

        // Phase 2: Connect to hardcoded bootstrap nodes if we need more peers.
        // This is the fallback for when coordinator cache and cached peers aren't enough.
        if all_connected.len() < min_connected && !bootstrap_nodes.is_empty() {
            let remaining: Vec<std::net::SocketAddr> = bootstrap_nodes
                .iter()
                .filter(|addr| !all_connected.contains(addr))
                .copied()
                .collect();

            // Round 1: Connect to all bootstrap peers in parallel
            let (succeeded, mut failed) = self
                .connect_peers_parallel_tracked(network, &remaining)
                .await;
            all_connected.extend(&succeeded);
            tracing::info!(
                "Phase 2 round 1: {}/{} bootstrap peers connected",
                succeeded.len(),
                remaining.len()
            );

            // Retry rounds for failed peers
            for round in 2..=3 {
                if failed.is_empty() {
                    break;
                }
                let delay = std::time::Duration::from_secs(if round == 2 { 10 } else { 15 });
                tracing::info!(
                    "Retrying {} failed peers in {}s (round {})",
                    failed.len(),
                    delay.as_secs(),
                    round
                );
                tokio::time::sleep(delay).await;

                let (succeeded, still_failed) =
                    self.connect_peers_parallel_tracked(network, &failed).await;
                all_connected.extend(&succeeded);
                failed = still_failed;
                tracing::info!(
                    "Phase 2 round {}: {} total peers connected",
                    round,
                    all_connected.len()
                );
            }

            if !failed.is_empty() {
                tracing::warn!(
                    "Could not connect to {} bootstrap peers: {:?}",
                    failed.len(),
                    failed
                );
            }
        }

        tracing::info!(
            "Network join complete. Connected to {} peers.",
            all_connected.len()
        );

        // Join the HyParView membership overlay via connected peers.
        if let Some(ref runtime) = self.gossip_runtime {
            let seeds: Vec<String> = all_connected.iter().map(|addr| addr.to_string()).collect();
            if !seeds.is_empty() {
                if let Err(e) = runtime.membership().join(seeds).await {
                    tracing::warn!("HyParView membership join failed: {e}");
                }
            }
        }

        // Start presence beacons after membership overlay is established.
        if let Some(ref pw) = self.presence {
            // Seed broadcast peers from both HyParView and ant-quic's live
            // connection table so beacons propagate even when HyParView's
            // active view lags behind the transport mesh.
            if let Some(ref runtime) = self.gossip_runtime {
                let active = runtime.membership().active_view();
                let active_view_count = active.len();
                let mut broadcast_peers = active;

                let mut connected_peer_count = 0usize;
                if let Some(ref net) = self.network {
                    let connected = net.connected_peers().await;
                    connected_peer_count = connected.len();
                    broadcast_peers.extend(
                        connected
                            .into_iter()
                            .map(|peer| saorsa_gossip_types::PeerId::new(peer.0)),
                    );
                }

                pw.manager().replace_broadcast_peers(broadcast_peers).await;
                let broadcast_peer_count = pw.manager().broadcast_peer_count().await;
                tracing::info!(
                    active_view_count,
                    connected_peer_count,
                    broadcast_peer_count,
                    "Presence seeded broadcast peers"
                );

                // Refresh broadcast_peers from HyParView and the live ant-quic
                // connection table every 30 s. Without this, agents that finish
                // join_network() before the mesh has formed can end up with an
                // empty/stale broadcast set forever. The 2026-04-26 live mesh
                // had full QUIC peer connectivity while HyParView active_view()
                // stayed at <= 1 peer, so the transport table is the source of
                // truth for presence fanout. Replace the fanout set each tick so
                // stale/disconnected peers do not accumulate and later wedge
                // presence delivery behind failed reconnect attempts.
                let pw_clone = pw.clone();
                let runtime_clone = runtime.clone();
                let network_clone = self.network.as_ref().map(std::sync::Arc::clone);
                let token = self.shutdown_token.clone();
                self.spawn_tracked(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                    interval.tick().await; // first tick fires immediately; startup already seeded
                    loop {
                        tokio::select! {
                            _ = interval.tick() => {}
                            // Inert until shutdown; then the 30s timer loop exits
                            // instead of being merely aborted.
                            _ = token.cancelled() => break,
                        }

                        let active = runtime_clone.membership().active_view();
                        let active_view_count = active.len();
                        let mut broadcast_peers = active;

                        let mut connected_peer_count = 0usize;
                        if let Some(ref net) = network_clone {
                            let connected = net.connected_peers().await;
                            connected_peer_count = connected.len();
                            broadcast_peers.extend(
                                connected
                                    .into_iter()
                                    .map(|peer| saorsa_gossip_types::PeerId::new(peer.0)),
                            );
                        }

                        pw_clone
                            .manager()
                            .replace_broadcast_peers(broadcast_peers)
                            .await;
                        let broadcast_peer_count = pw_clone.manager().broadcast_peer_count().await;
                        tracing::info!(
                            active_view_count,
                            connected_peer_count,
                            broadcast_peer_count,
                            "Presence broadcast peer refresh"
                        );
                    }
                });
            }

            // Populate address hints from network status for beacon metadata.
            //
            // Presence beacons propagate over global gossip — filter to only
            // globally-advertisable addresses. LAN discovery is ant-quic's
            // mDNS job, not ours. Also exclude `status.local_addr` which is
            // typically the wildcard `[::]:5483` and never a dialable target.
            if let Some(ref net) = self.network {
                if let Some(status) = net.node_status().await {
                    let hints: Vec<String> = status
                        .external_addrs
                        .iter()
                        .filter(|a| is_publicly_advertisable(**a))
                        .map(|a| a.to_string())
                        .collect();
                    pw.manager().set_addr_hints(hints).await;
                }
            }

            // Shutdown race (issue #116): skip starting presence beacons / event
            // loop if shutdown began mid-bootstrap; Agent::shutdown() runs
            // pw.shutdown() AFTER cancel(), so checking here ensures we never
            // start beacons that pw.shutdown() already stopped.
            if !self.shutdown_token.is_cancelled() {
                if pw.config().enable_beacons {
                    if let Err(e) = pw
                        .manager()
                        .start_beacons(pw.config().beacon_interval_secs)
                        .await
                    {
                        tracing::warn!("Failed to start presence beacons: {e}");
                    } else {
                        tracing::info!(
                            "Presence beacons started (interval={}s)",
                            pw.config().beacon_interval_secs
                        );
                    }
                }

                // Start the presence event-emission loop so that subscribers
                // automatically receive AgentOnline/AgentOffline events after
                // join_network() returns.
                pw.start_event_loop(std::sync::Arc::clone(&self.identity_discovery_cache))
                    .await;
                tracing::debug!("Presence event loop started");
            }
        }

        if let Err(e) = self.announce_identity(false, false).await {
            tracing::warn!("Initial identity announcement failed: {}", e);
        }
        if let Err(e) = self.start_identity_heartbeat().await {
            tracing::warn!("Failed to start identity heartbeat: {e}");
        }
        if let Err(e) = self.start_discovery_cache_reaper().await {
            tracing::warn!("Failed to start discovery cache reaper: {e}");
        }

        // Schedule a fresh re-announcement after gossip topology stabilizes.
        // The initial publish fires before PlumTree has formed eager-push links,
        // so peers that connected after the first announce won't see it.
        // A fresh announcement (new message ID) is required because PlumTree
        // deduplicates by message ID — replaying identical bytes would be silently
        // dropped by peers that already received the first announcement.
        if let (Some(ref runtime), Some(ref network)) = (&self.gossip_runtime, &self.network) {
            let ctx = HeartbeatContext {
                identity: std::sync::Arc::clone(&self.identity),
                runtime: std::sync::Arc::clone(runtime),
                network: std::sync::Arc::clone(network),
                interval_secs: self.heartbeat_interval_secs,
                cache: std::sync::Arc::clone(&self.identity_discovery_cache),
                machine_cache: std::sync::Arc::clone(&self.machine_discovery_cache),
                user_identity_consented: std::sync::Arc::clone(&self.user_identity_consented),
                allow_local_discovery_addrs: allow_local_discovery_addresses(network.config()),
                revocation_set: std::sync::Arc::clone(&self.revocation_set),
            };
            // Routed through spawn_tracked (issue #116) so a shutdown racing
            // bootstrap refuses to start it once the registry is closed; it is
            // a one-shot self-completing task so no token arm is needed.
            self.spawn_tracked(async move {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                if let Err(e) = ctx.announce().await {
                    tracing::warn!("Delayed identity re-announcement failed: {e}");
                } else {
                    tracing::info!(
                        "Delayed identity re-announcement sent (gossip mesh stabilized)"
                    );
                }
            });
        }

        if let Err(e) = self.start_capability_advert_service().await {
            tracing::warn!("failed to start capability advert service: {e}");
        }

        Ok(())
    }

    /// Clone the shared capability store.
    #[must_use]
    pub fn capability_store(&self) -> std::sync::Arc<dm_capability::CapabilityStore> {
        std::sync::Arc::clone(&self.capability_store)
    }

    /// Start or restart the mesh-wide DM capability advert service.
    ///
    /// The service publishes this agent's current DM capability and subscribes
    /// to peer adverts. It is idempotent: a fresh service replaces any previous
    /// one. Daemons call this independently of `join_network()` completion so
    /// a slow bootstrap pass cannot leave DM capability discovery disabled.
    ///
    /// # Errors
    ///
    /// Returns an error if no gossip runtime is configured yet or the advert
    /// service cannot subscribe/publish on its topic.
    pub async fn start_capability_advert_service(&self) -> error::Result<()> {
        let runtime = self.gossip_runtime.as_ref().ok_or_else(|| {
            error::IdentityError::Storage(std::io::Error::other(
                "cannot start capability advert service: no gossip runtime configured",
            ))
        })?;

        let signing = std::sync::Arc::new(gossip::SigningContext::from_keypair(
            self.identity.agent_keypair(),
        ));
        let caps_rx = self.dm_capabilities_tx.subscribe();
        let service = dm_capability_service::CapabilityAdvertService::spawn_default(
            std::sync::Arc::clone(runtime.pubsub()),
            signing,
            self.identity.agent_id(),
            self.identity.machine_id(),
            caps_rx,
            std::sync::Arc::clone(&self.capability_store),
        )
        .await
        .map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!(
                "capability advert service spawn failed: {e}"
            )))
        })?;

        let mut guard = self.capability_advert_service.lock().await;
        // Shutdown race (issue #116): if shutdown began while we were spawning,
        // abort the freshly-spawned service instead of storing it. Checked under
        // the same lock shutdown() takes the service from, so it can't leak.
        if self.shutdown_token.is_cancelled() {
            service.abort();
            return Ok(());
        }
        if let Some(prev) = guard.take() {
            prev.abort();
        }
        *guard = Some(service);
        tracing::info!("Capability advert service started");
        Ok(())
    }

    /// Clone the shared DM in-flight ACK registry.
    #[must_use]
    pub fn dm_inflight_acks(&self) -> std::sync::Arc<dm::InFlightAcks> {
        std::sync::Arc::clone(&self.dm_inflight_acks)
    }

    /// Clone the shared recent-delivery dedupe cache.
    #[must_use]
    pub fn recent_delivery_cache(&self) -> std::sync::Arc<dm::RecentDeliveryCache> {
        std::sync::Arc::clone(&self.recent_delivery_cache)
    }

    /// Spawn the DM inbox service backed by the given KEM keypair.
    /// Idempotent — the prior service is aborted before spawning new.
    ///
    /// # Errors
    ///
    /// Returns an error if no gossip runtime is configured.
    pub async fn start_dm_inbox(
        &self,
        kem_keypair: std::sync::Arc<groups::kem_envelope::AgentKemKeypair>,
        config: dm_inbox::DmInboxConfig,
    ) -> error::Result<()> {
        let runtime = self.gossip_runtime.as_ref().ok_or_else(|| {
            error::IdentityError::Storage(std::io::Error::other(
                "cannot start DM inbox: no gossip runtime configured",
            ))
        })?;
        let signing = std::sync::Arc::new(gossip::SigningContext::from_keypair(
            self.identity.agent_keypair(),
        ));
        let service = dm_inbox::DmInboxService::spawn(
            std::sync::Arc::clone(runtime.pubsub()),
            signing,
            self.identity.agent_id(),
            self.identity.machine_id(),
            std::sync::Arc::clone(&kem_keypair),
            std::sync::Arc::clone(&self.direct_messaging),
            std::sync::Arc::clone(&self.contact_store),
            std::sync::Arc::clone(&self.dm_inflight_acks),
            std::sync::Arc::clone(&self.recent_delivery_cache),
            config,
            std::sync::Arc::clone(&self.revocation_set),
        )
        .await
        .map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!(
                "DM inbox spawn failed: {e}"
            )))
        })?;
        let mut guard = self.dm_inbox_service.lock().await;
        // Shutdown race (issue #116): if shutdown began while we were spawning,
        // abort the freshly-spawned service instead of storing it (and skip the
        // capability upgrade below). Checked under the same lock stop_dm_inbox
        // takes the service from, so it can't leak.
        if self.shutdown_token.is_cancelled() {
            service.abort();
            return Ok(());
        }
        if let Some(prev) = guard.take() {
            prev.abort();
        }
        *guard = Some(service);

        // Upgrade our advertised capabilities so peers stop falling back
        // to the raw-QUIC path. The capability advert service watches
        // this channel and republishes immediately on change.
        let upgraded =
            dm::DmCapabilities::pending().with_kem_public_key(kem_keypair.public_bytes.clone());
        // send_replace stores the value even when no receiver is subscribed
        // yet; a plain send() drops the upgrade if this runs before the
        // capability advert service subscribes, leaving peers cached on
        // gossip_inbox=false and forcing the raw-QUIC fallback that fails
        // across NAT (issue #101).
        self.dm_capabilities_tx.send_replace(upgraded);
        tracing::info!("DM inbox service started");
        Ok(())
    }

    /// Stop the DM inbox service, if running. Idempotent.
    pub async fn stop_dm_inbox(&self) {
        let mut guard = self.dm_inbox_service.lock().await;
        if let Some(service) = guard.take() {
            service.abort();
        }
    }

    /// Connect to cached peers in parallel, returning (succeeded, failed) peer lists.
    async fn connect_cached_peers_parallel_tracked(
        &self,
        network: &std::sync::Arc<network::NetworkNode>,
        peers: &[ant_quic::CachedPeer],
    ) -> (Vec<std::net::SocketAddr>, Vec<ant_quic::PeerId>) {
        use tokio::time::{timeout, Duration};
        const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

        let handles: Vec<_> = peers
            .iter()
            .map(|peer| {
                let net = network.clone();
                let peer_id = peer.peer_id;
                tokio::spawn(async move {
                    tracing::debug!("Connecting to cached peer: {:?}", peer_id);
                    match timeout(CONNECT_TIMEOUT, net.connect_cached_peer(peer_id)).await {
                        Ok(Ok(addr)) => {
                            tracing::info!("Connected to cached peer {:?} at {}", peer_id, addr);
                            Ok(addr)
                        }
                        Ok(Err(e)) => {
                            tracing::warn!("Failed to connect to cached peer {:?}: {}", peer_id, e);
                            Err(peer_id)
                        }
                        Err(_) => {
                            tracing::warn!(
                                "Connection to cached peer {:?} timed out after {}s",
                                peer_id,
                                CONNECT_TIMEOUT.as_secs()
                            );
                            Err(peer_id)
                        }
                    }
                })
            })
            .collect();

        let mut succeeded = Vec::new();
        let mut failed = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(addr)) => succeeded.push(addr),
                Ok(Err(peer_id)) => failed.push(peer_id),
                Err(e) => tracing::error!("Connection task panicked: {}", e),
            }
        }
        (succeeded, failed)
    }

    /// Connect to multiple peers in parallel, returning (succeeded, failed) address lists.
    async fn connect_peers_parallel_tracked(
        &self,
        network: &std::sync::Arc<network::NetworkNode>,
        addrs: &[std::net::SocketAddr],
    ) -> (Vec<std::net::SocketAddr>, Vec<std::net::SocketAddr>) {
        use tokio::time::{timeout, Duration};

        // Per-connection timeout prevents hanging when connecting to
        // ourselves or to unreachable addresses.
        const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

        let handles: Vec<_> = addrs
            .iter()
            .map(|addr| {
                let net = network.clone();
                let addr = *addr;
                tokio::spawn(async move {
                    tracing::debug!("Connecting to peer: {}", addr);
                    match timeout(CONNECT_TIMEOUT, net.connect_addr(addr)).await {
                        Ok(Ok(_)) => {
                            tracing::info!("Connected to peer: {}", addr);
                            Ok(addr)
                        }
                        Ok(Err(e)) => {
                            tracing::warn!("Failed to connect to {}: {}", addr, e);
                            Err(addr)
                        }
                        Err(_) => {
                            tracing::warn!(
                                "Connection to {} timed out after {}s",
                                addr,
                                CONNECT_TIMEOUT.as_secs()
                            );
                            Err(addr)
                        }
                    }
                })
            })
            .collect();

        let mut succeeded = Vec::new();
        let mut failed = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(addr)) => succeeded.push(addr),
                Ok(Err(addr)) => failed.push(addr),
                Err(e) => tracing::error!("Connection task panicked: {}", e),
            }
        }
        (succeeded, failed)
    }

    /// Subscribe to messages on a given topic.
    ///
    /// Returns a [`gossip::Subscription`] that yields messages as they arrive
    /// through the gossip network.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Gossip runtime is not initialized (configure agent with network first)
    pub async fn subscribe(&self, topic: &str) -> error::Result<Subscription> {
        let runtime = self.gossip_runtime.as_ref().ok_or_else(|| {
            error::IdentityError::Storage(std::io::Error::other(
                "gossip runtime not initialized - configure agent with network first",
            ))
        })?;
        Ok(runtime.pubsub().subscribe(topic.to_string()).await)
    }

    /// Publish a message to a topic.
    ///
    /// The message will propagate through the gossip network via
    /// epidemic broadcast — every agent that receives it will
    /// relay it to its neighbours.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Gossip runtime is not initialized (configure agent with network first)
    /// - Message encoding or broadcast fails
    pub async fn publish(&self, topic: &str, payload: Vec<u8>) -> error::Result<()> {
        let runtime = self.gossip_runtime.as_ref().ok_or_else(|| {
            error::IdentityError::Storage(std::io::Error::other(
                "gossip runtime not initialized - configure agent with network first",
            ))
        })?;
        runtime
            .pubsub()
            .publish(topic.to_string(), bytes::Bytes::from(payload))
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "publish failed: {}",
                    e
                )))
            })
    }

    /// Get connected peer IDs.
    ///
    /// Returns the list of peers currently connected via the gossip network.
    ///
    /// # Errors
    ///
    /// Returns an error if the network is not initialized.
    pub async fn peers(&self) -> error::Result<Vec<saorsa_gossip_types::PeerId>> {
        let network = self.network.as_ref().ok_or_else(|| {
            error::IdentityError::Storage(std::io::Error::other(
                "network not initialized - configure agent with network first",
            ))
        })?;
        let ant_peers = network.connected_peers().await;
        Ok(ant_peers
            .into_iter()
            .map(|p| saorsa_gossip_types::PeerId::new(p.0))
            .collect())
    }

    /// Get online agents.
    ///
    /// Returns agent IDs discovered from signed identity announcements.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn presence(&self) -> error::Result<Vec<identity::AgentId>> {
        self.start_identity_listener().await?;
        let cutoff = Self::unix_timestamp_secs().saturating_sub(self.identity_ttl_secs);
        let mut agents: Vec<_> = self
            .identity_discovery_cache
            .read()
            .await
            .values()
            .filter(|a| discovery_record_is_live(a.announced_at, a.last_seen, cutoff))
            .map(|a| a.agent_id)
            .collect();
        agents.sort_by_key(|a| a.0);
        Ok(agents)
    }

    /// Subscribe to presence events (agent online/offline notifications).
    ///
    /// Returns a [`tokio::sync::broadcast::Receiver<PresenceEvent>`] that yields
    /// [`presence::PresenceEvent`] values as agents come online or go offline.
    ///
    /// The diff-based event emission loop is started lazily on the first call to this
    /// method (or when [`join_network`](Agent::join_network) is called). Subsequent
    /// calls return independent receivers on the same broadcast channel.
    ///
    /// # Errors
    ///
    /// Returns [`error::NetworkError::NodeError`] if this agent was built
    /// without a network configuration (i.e. no `with_network_config` on the builder).
    pub async fn subscribe_presence(
        &self,
    ) -> error::NetworkResult<tokio::sync::broadcast::Receiver<presence::PresenceEvent>> {
        let pw = self.presence.as_ref().ok_or_else(|| {
            error::NetworkError::NodeError("presence system not initialized".to_string())
        })?;
        // Ensure the event loop is running.
        pw.start_event_loop(std::sync::Arc::clone(&self.identity_discovery_cache))
            .await;
        Ok(pw.subscribe_events())
    }

    /// Look up a single agent in the local discovery cache.
    ///
    /// Returns `None` if the agent is not currently cached.  No network I/O is
    /// performed — use [`discover_agent_by_id`](Agent::discover_agent_by_id) for
    /// an active lookup that queries the network.
    pub async fn cached_agent(&self, id: &identity::AgentId) -> Option<DiscoveredAgent> {
        self.identity_discovery_cache.read().await.get(id).cloned()
    }

    /// Check whether a claimed `AgentId` is verified as belonging to the
    /// given `MachineId` in the identity discovery cache.
    ///
    /// Returns `true` if the cache contains a signed identity announcement
    /// binding this agent to this machine.  Returns `false` if:
    /// - the agent is unknown or bound to a different machine, OR
    /// - the agent or its bound machine has been revoked, OR
    /// - the cached agent certificate has expired (past `not_after` + 300 s
    ///   clock skew).
    ///
    /// Revocation is fail-closed: a revoked peer is always refused, even if
    /// a certificate mismatch or race condition has cleared the cache entry.
    /// Absent expiry (`cert_not_after == None`) is fail-open: treated as
    /// "never expires" to preserve compatibility with pre-#130 peers.
    pub async fn is_agent_machine_verified(
        &self,
        agent_id: &identity::AgentId,
        machine_id: &identity::MachineId,
    ) -> bool {
        // Fail-closed on revocation: check before touching the discovery cache
        // so a racing cache-eviction cannot create a window where a revoked
        // peer appears verified.
        {
            let revoked = self.revocation_set.read().await;
            if revoked.is_agent_revoked(agent_id) || revoked.is_machine_revoked(machine_id) {
                return false;
            }
        }

        let cache = self.identity_discovery_cache.read().await;
        let Some(entry) = cache.get(agent_id) else {
            return false;
        };
        if entry.machine_id != *machine_id {
            return false;
        }
        // Fail-open on absent expiry (pre-#130 peers have no cert / no not_after).
        if identity::is_expired(entry.cert_not_after, Self::unix_timestamp_secs()) {
            return false;
        }
        true
    }

    /// Return the shared revocation set.
    ///
    /// Callers that need to publish a new revocation record should call
    /// [`revoke`](Agent::revoke) instead; this accessor is for gate checks
    /// and diagnostics.
    pub fn revocation_set(&self) -> std::sync::Arc<tokio::sync::RwLock<revocation::RevocationSet>> {
        std::sync::Arc::clone(&self.revocation_set)
    }

    /// Return a snapshot of all known revocation records.
    ///
    /// This is a read-only snapshot; the in-memory set grows only (no un-revocation).
    pub async fn revocation_records(&self) -> Vec<revocation::RevocationRecord> {
        self.revocation_set.read().await.all_records()
    }

    /// Sign and publish a revocation for the given subject, then persist it
    /// locally and apply it immediately.
    ///
    /// The issuer keypair must satisfy one of the two authority rules in
    /// [`revocation::RevocationRecord::verify_authority`]:
    /// - **Self-revocation**: the issuer keypair's AgentId equals the subject's AgentId.
    /// - **Issuer-revocation**: the issuer is the user who signed the subject
    ///   agent's certificate (the certificate must be passed as `subject_cert`).
    ///
    /// On success, the record is inserted into the local revocation set,
    /// persisted to `revocations.bin`, published on [`REVOCATION_TOPIC`], and
    /// the subject is evicted from all discovery caches.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails, the authority check fails, or the
    /// gossip publish fails.
    pub async fn revoke(
        &self,
        issuer_keypair: &identity::AgentKeypair,
        subject: revocation::RevokedSubject,
        reason: Option<String>,
        subject_cert: Option<&identity::AgentCertificate>,
    ) -> error::Result<revocation::RevocationRecord> {
        let now = Self::unix_timestamp_secs();
        let record = revocation::RevocationRecord::sign(
            subject,
            issuer_keypair.public_key(),
            issuer_keypair.secret_key(),
            now,
            reason,
        )?;
        self.apply_and_publish_revocation(record.clone(), subject_cert)
            .await?;
        Ok(record)
    }

    /// Apply a revocation record to the local set, persist, publish, and evict.
    ///
    /// Used both by [`revoke`](Agent::revoke) (self-issued) and the gossip
    /// subscription loop (received from a peer).
    async fn apply_and_publish_revocation(
        &self,
        record: revocation::RevocationRecord,
        subject_cert: Option<&identity::AgentCertificate>,
    ) -> error::Result<()> {
        // 1. Verify and insert.
        {
            let mut set = self.revocation_set.write().await;
            if let Err(e) = set.verify_and_insert(record.clone(), subject_cert) {
                return Err(error::IdentityError::CertificateVerification(format!(
                    "revocation rejected: {e}"
                )));
            }
        }

        // 2. Persist.
        storage::save_revocation_set(
            &*self.revocation_set.read().await,
            self.identity_dir.as_deref(),
        )
        .await?;

        // 3. Evict from caches.
        self.evict_revoked_subject(&record.subject).await;

        // 4. Publish on gossip (best-effort — local enforcement happens regardless).
        if let Some(rt) = &self.gossip_runtime {
            let records = self.revocation_set.read().await.all_records();
            match bincode::serialize(&records) {
                Ok(bytes) if !bytes.is_empty() => {
                    let _ = rt
                        .pubsub()
                        .publish(REVOCATION_TOPIC.to_string(), bytes::Bytes::from(bytes))
                        .await;
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Evict a revoked subject from all discovery caches.
    async fn evict_revoked_subject(&self, subject: &revocation::RevokedSubject) {
        // NOTE: this evicts the identity/machine discovery caches and the
        // contact store, but does NOT purge the ant-quic bootstrap cache. A
        // revoked peer's address can therefore linger there; this is a residual
        // (not a hole) because EP1 re-rejects the peer's announcement on every
        // ingest, so it can never re-enter the verified path. Bootstrap-cache
        // purge on eviction is tracked as a follow-up.
        match subject {
            revocation::RevokedSubject::Agent(agent_id) => {
                // Remove from identity cache, which also starves the verified annotation.
                let mut cache = self.identity_discovery_cache.write().await;
                if let Some(entry) = cache.remove(agent_id) {
                    // Also evict the linked machine so it cannot be dialed.
                    drop(cache);
                    let mut mcache = self.machine_discovery_cache.write().await;
                    mcache.remove(&entry.machine_id);
                } else {
                    drop(cache);
                }
                // Best-effort: mark as Blocked in the contact store so that
                // trust evaluation also refuses the agent on any late-arriving path.
                {
                    let mut cs = self.contact_store.write().await;
                    cs.set_trust(agent_id, contacts::TrustLevel::Blocked);
                }
                tracing::info!(
                    agent = %hex::encode(agent_id.as_bytes()),
                    "evicted revoked agent from discovery cache"
                );
            }
            revocation::RevokedSubject::Machine(machine_id) => {
                let mut mcache = self.machine_discovery_cache.write().await;
                mcache.remove(machine_id);
                drop(mcache);
                // Also evict any agents linked to this machine.
                let mut cache = self.identity_discovery_cache.write().await;
                cache.retain(|_, agent| agent.machine_id != *machine_id);
                tracing::info!(
                    machine = %hex::encode(machine_id.as_bytes()),
                    "evicted revoked machine from discovery cache"
                );
            }
        }
    }

    /// Discover agents via Friend-of-a-Friend (FOAF) random walk.
    ///
    /// Initiates a FOAF query on the global presence topic with the given `ttl`
    /// (maximum hop count) and `timeout_ms` (response collection window).
    ///
    /// Returned entries are resolved against the local identity discovery cache
    /// so that known agents are returned with full identity data.  Unknown peers
    /// are included with a minimal entry (addresses only) that will be enriched
    /// once their identity heartbeat arrives.
    ///
    /// # Arguments
    ///
    /// * `ttl` — Maximum hop count for the random walk (`1`–`5`). Typical: `2`.
    /// * `timeout_ms` — Query timeout in milliseconds. Typical: `5000`.
    ///
    /// # Errors
    ///
    /// Returns [`error::NetworkError::NodeError`] if no network config was provided.
    pub async fn discover_agents_foaf(
        &self,
        ttl: u8,
        timeout_ms: u64,
    ) -> error::NetworkResult<Vec<DiscoveredAgent>> {
        let pw = self.presence.as_ref().ok_or_else(|| {
            error::NetworkError::NodeError("presence system not initialized".to_string())
        })?;

        let topic = presence::global_presence_topic();
        let raw_results: Vec<(
            saorsa_gossip_types::PeerId,
            saorsa_gossip_types::PresenceRecord,
        )> = pw
            .manager()
            .initiate_foaf_query(topic, ttl, timeout_ms)
            .await
            .map_err(|e| error::NetworkError::NodeError(e.to_string()))?;

        let cache = self.identity_discovery_cache.read().await;

        // Convert and deduplicate by agent_id.
        let mut seen: std::collections::HashSet<identity::AgentId> =
            std::collections::HashSet::new();
        let mut agents: Vec<DiscoveredAgent> = Vec::with_capacity(raw_results.len());

        for (peer_id, record) in &raw_results {
            if let Some(agent) =
                presence::presence_record_to_discovered_agent(*peer_id, record, &cache)
            {
                if seen.insert(agent.agent_id) {
                    agents.push(agent);
                }
            }
        }

        Ok(agents)
    }

    /// Discover a specific agent by their [`identity::AgentId`] via FOAF random walk.
    ///
    /// Fast-path: checks the local identity discovery cache first and returns
    /// immediately if the agent is already known.
    ///
    /// Slow-path: performs a FOAF random walk (see [`discover_agents_foaf`](Agent::discover_agents_foaf))
    /// and searches the results for a matching `AgentId`.
    ///
    /// Returns `None` if the agent is not found within the given `ttl` and `timeout_ms`.
    ///
    /// # Errors
    ///
    /// Returns [`error::NetworkError::NodeCreation`] if no network config was provided.
    pub async fn discover_agent_by_id(
        &self,
        target_id: identity::AgentId,
        ttl: u8,
        timeout_ms: u64,
    ) -> error::NetworkResult<Option<DiscoveredAgent>> {
        // Fast path: already in local cache.
        {
            let cache = self.identity_discovery_cache.read().await;
            if let Some(agent) = cache.get(&target_id) {
                return Ok(Some(agent.clone()));
            }
        }

        // Slow path: FOAF random walk.
        let agents = self.discover_agents_foaf(ttl, timeout_ms).await?;
        Ok(agents.into_iter().find(|a| a.agent_id == target_id))
    }

    /// Find an agent by ID, returning its known addresses.
    ///
    /// Performs a three-stage lookup:
    /// 1. **Cache hit** — return addresses immediately if the agent has already
    ///    been discovered.
    /// 2. **Shard subscription** — subscribe to the agent's identity shard topic
    ///    and wait up to 5 seconds for a heartbeat announcement.
    /// 3. **Rendezvous** — subscribe to the agent's rendezvous shard topic and
    ///    wait up to 5 seconds for a `ProviderSummary` advertisement.  This
    ///    works even when the two agents are on different gossip overlay clusters.
    ///
    /// Returns `None` if the agent is not found within the combined deadline.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn find_agent(
        &self,
        agent_id: identity::AgentId,
    ) -> error::Result<Option<Vec<std::net::SocketAddr>>> {
        self.start_identity_listener().await?;

        // Stage 1: cache hit.
        if let Some(addrs) = self
            .identity_discovery_cache
            .read()
            .await
            .get(&agent_id)
            .map(|e| e.addresses.clone())
        {
            return Ok(Some(addrs));
        }

        // Stage 2: subscribe to the agent's identity shard topic and wait up to 5 s.
        let runtime = match self.gossip_runtime.as_ref() {
            Some(r) => r,
            None => return Ok(None),
        };
        let shard_topic = shard_topic_for_agent(&agent_id);
        let mut sub = runtime.pubsub().subscribe(shard_topic).await;
        let cache = std::sync::Arc::clone(&self.identity_discovery_cache);
        let machine_cache = std::sync::Arc::clone(&self.machine_discovery_cache);
        let allow_local_scope = self
            .network
            .as_ref()
            .is_some_and(|network| allow_local_discovery_addresses(network.config()));
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);

        loop {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let timeout = tokio::time::sleep_until(deadline);
            tokio::select! {
                Some(msg) = sub.recv() => {
                    if let Ok(ann) = deserialize_identity_announcement(&msg.payload) {
                        if ann.verify().is_ok() && ann.agent_id == agent_id {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map_or(0, |d| d.as_secs());
                            let filtered = filter_discovery_announcement_addrs(
                                ann.addresses.iter().copied(),
                                allow_local_scope,
                            );
                            let addrs = filtered.clone();
                            let discovered_agent = DiscoveredAgent {
                                agent_id: ann.agent_id,
                                machine_id: ann.machine_id,
                                user_id: ann.user_id,
                                addresses: filtered,
                                announced_at: ann.announced_at,
                                last_seen: now,
                                machine_public_key: ann.machine_public_key.clone(),
                                nat_type: ann.nat_type.clone(),
                                can_receive_direct: ann.can_receive_direct,
                                is_relay: ann.is_relay,
                                is_coordinator: ann.is_coordinator,
                                reachable_via: ann.reachable_via.clone(),
                                relay_candidates: ann.relay_candidates.clone(),
                                cert_not_after: ann
                                    .agent_certificate
                                    .as_ref()
                                    .and_then(|c| c.not_after()),
                                agent_certificate: ann.agent_certificate.clone(),
                            };
                            upsert_discovered_machine_from_agent(&machine_cache, &discovered_agent)
                                .await;
                            upsert_discovered_agent(&cache, discovered_agent).await;
                            return Ok(Some(addrs));
                        }
                    }
                }
                _ = timeout => break,
            }
        }

        // Stage 3: rendezvous shard subscription — wait up to 5 s.
        // Cache the result so subsequent connect_to_agent / send_direct can find it.
        if let Some(addrs) = self.find_agent_rendezvous(agent_id, 5).await? {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            upsert_discovered_agent(
                &cache,
                DiscoveredAgent {
                    agent_id,
                    machine_id: identity::MachineId([0u8; 32]),
                    user_id: None,
                    addresses: addrs.clone(),
                    announced_at: now,
                    last_seen: now,
                    machine_public_key: Vec::new(),
                    nat_type: None,
                    can_receive_direct: None,
                    is_relay: None,
                    is_coordinator: None,
                    reachable_via: Vec::new(),
                    relay_candidates: Vec::new(),
                    cert_not_after: None,
                    agent_certificate: None,
                },
            )
            .await;
            return Ok(Some(addrs));
        }

        Ok(None)
    }

    /// Find a machine by ID and return its current endpoint record.
    ///
    /// Performs a cache lookup first, then subscribes to the machine's shard
    /// topic and waits up to `timeout_secs` for a signed machine announcement.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn find_machine(
        &self,
        machine_id: identity::MachineId,
        timeout_secs: u64,
    ) -> error::Result<Option<DiscoveredMachine>> {
        self.start_identity_listener().await?;

        if let Some(machine) = self
            .machine_discovery_cache
            .read()
            .await
            .get(&machine_id)
            .cloned()
        {
            return Ok(Some(machine));
        }

        let runtime = match self.gossip_runtime.as_ref() {
            Some(r) => r,
            None => return Ok(None),
        };
        let shard_topic = shard_topic_for_machine(&machine_id);
        let mut sub = runtime.pubsub().subscribe(shard_topic).await;
        let machine_cache = std::sync::Arc::clone(&self.machine_discovery_cache);
        let allow_local_scope = self
            .network
            .as_ref()
            .is_some_and(|network| allow_local_discovery_addresses(network.config()));
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs.clamp(1, 60));

        loop {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let timeout = tokio::time::sleep_until(deadline);
            tokio::select! {
                Some(msg) = sub.recv() => {
                    if let Ok(ann) = deserialize_machine_announcement(&msg.payload) {
                        if ann.verify().is_ok() && ann.machine_id == machine_id {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map_or(0, |d| d.as_secs());
                            let filtered = filter_discovery_announcement_addrs(
                                ann.addresses.iter().copied(),
                                allow_local_scope,
                            );
                            let discovered = DiscoveredMachine::from_machine_announcement(
                                &ann,
                                filtered,
                                now,
                            );
                            upsert_discovered_machine(&machine_cache, discovered).await;
                            return Ok(machine_cache.read().await.get(&machine_id).cloned());
                        }
                    }
                }
                _ = timeout => break,
            }
        }

        Ok(None)
    }

    /// Find all discovered agents claiming ownership by the given [`identity::UserId`].
    ///
    /// Only returns agents that announced with `include_user_identity: true`
    /// (i.e., agents whose [`DiscoveredAgent::user_id`] is `Some`).
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user identity to search for
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn find_agents_by_user(
        &self,
        user_id: identity::UserId,
    ) -> error::Result<Vec<DiscoveredAgent>> {
        self.start_identity_listener().await?;
        let cutoff = Self::unix_timestamp_secs().saturating_sub(self.identity_ttl_secs);
        Ok(self
            .identity_discovery_cache
            .read()
            .await
            .values()
            .filter(|a| {
                discovery_record_is_live(a.announced_at, a.last_seen, cutoff)
                    && a.user_id == Some(user_id)
            })
            .cloned()
            .collect())
    }

    /// Return the local socket address this agent's network node is bound to, if any.
    ///
    /// Returns `None` if no network has been configured or if the bind address is
    /// not yet known.
    ///
    /// **Note:** If the node was configured with port 0, this returns port 0.
    /// Use [`bound_addr()`](Self::bound_addr) to get the OS-assigned port.
    #[must_use]
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.network.as_ref().and_then(|n| n.local_addr())
    }

    /// Return the actual bound address from the QUIC endpoint.
    ///
    /// Unlike [`local_addr()`](Self::local_addr) which returns the configured value
    /// (possibly port 0), this queries the running endpoint for the real OS-assigned
    /// address. Returns `None` if no network has been configured.
    pub async fn bound_addr(&self) -> Option<std::net::SocketAddr> {
        if let Some(ref network) = self.network {
            let addr = network.bound_addr().await;
            // On dual-stack systems, bound_addr may return [::]:port even when
            // we bound to 127.0.0.1. Normalize to IPv4 if the original config
            // was IPv4.
            match (addr, self.local_addr()) {
                (Some(bound), Some(config)) if config.is_ipv4() && bound.is_ipv6() => {
                    Some(std::net::SocketAddr::new(config.ip(), bound.port()))
                }
                (Some(bound), _) => Some(bound),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Build a signed [`IdentityAnnouncement`] for this agent.
    ///
    /// Delegates to the internal `build_identity_announcement` method.
    ///
    /// # Errors
    ///
    /// Returns an error if key signing fails or human consent is required but not given.
    pub fn build_announcement(
        &self,
        include_user: bool,
        consent: bool,
    ) -> error::Result<IdentityAnnouncement> {
        self.build_identity_announcement(include_user, consent)
    }

    /// Build a signed [`MachineAnnouncement`] for this daemon's transport
    /// endpoint.
    ///
    /// This sync helper uses currently known local interface addresses and
    /// leaves async NAT/reachability fields as `None`; live network announces
    /// populate those fields from `NetworkNode::node_status()`.
    ///
    /// # Errors
    ///
    /// Returns an error if key signing fails.
    pub fn build_machine_announcement(&self) -> error::Result<MachineAnnouncement> {
        build_machine_announcement_for_identity(
            &self.identity,
            self.announcement_addresses(),
            Self::unix_timestamp_secs(),
            None,
            Vec::new(),
            Vec::new(),
            self.network
                .as_ref()
                .is_some_and(|network| allow_local_discovery_addresses(network.config())),
        )
    }

    /// Start the background identity heartbeat task.
    ///
    /// Idempotent — if the heartbeat is already running, returns `Ok(())` immediately.
    /// The heartbeat re-announces this agent's identity at `heartbeat_interval_secs`
    /// intervals so that late-joining peers can discover it without waiting for a
    /// Start the network event reconciliation listener.
    ///
    /// This bridges transport-level peer connect/disconnect events into the
    /// agent-level direct messaging registry so inbound accepted connections are
    /// usable for reverse direct sends before the first inbound direct payload.
    fn start_network_event_listener(&self) {
        if self
            .network_event_listener_started
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }

        let Some(network) = self.network.as_ref().map(std::sync::Arc::clone) else {
            return;
        };
        let cache = std::sync::Arc::clone(&self.identity_discovery_cache);
        let dm = std::sync::Arc::clone(&self.direct_messaging);

        let lifecycle_network = std::sync::Arc::clone(&network);
        let lifecycle_dm = std::sync::Arc::clone(&dm);
        let event_token = self.shutdown_token.clone();
        let lifecycle_token = self.shutdown_token.clone();

        self.spawn_tracked(async move {
            let mut rx = network.subscribe();
            tracing::info!("Network event reconciliation listener started");

            loop {
                let event = tokio::select! {
                    // event_sender is a NetworkNode struct field that outlives
                    // network.shutdown(), so this loop never ended on shutdown
                    // before; the token is what stops it now.
                    _ = event_token.cancelled() => break,
                    recv = rx.recv() => match recv {
                        Ok(event) => event,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!("Network event listener lagged by {skipped} events");
                            continue;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    },
                };

                match event {
                    network::NetworkEvent::PeerConnected { peer_id, .. } => {
                        let machine_id = identity::MachineId(peer_id);
                        let cached_agent_id = {
                            let cache = cache.read().await;
                            cache
                                .values()
                                .find(|entry| entry.machine_id == machine_id)
                                .map(|entry| entry.agent_id)
                        };
                        let agent_id = match cached_agent_id {
                            Some(agent_id) => Some(agent_id),
                            None => dm.lookup_agent(&machine_id).await,
                        };
                        if let Some(agent_id) = agent_id {
                            dm.mark_connected(agent_id, machine_id).await;
                        }
                    }
                    network::NetworkEvent::PeerDisconnected { peer_id } => {
                        let machine_id = identity::MachineId(peer_id);
                        let cached_agent_id = {
                            let cache = cache.read().await;
                            cache
                                .values()
                                .find(|entry| entry.machine_id == machine_id)
                                .map(|entry| entry.agent_id)
                        };
                        let agent_id = match cached_agent_id {
                            Some(agent_id) => Some(agent_id),
                            None => dm.lookup_agent(&machine_id).await,
                        };
                        if let Some(agent_id) = agent_id {
                            dm.mark_disconnected(&agent_id).await;
                        }
                    }
                    _ => {}
                }
            }
        });

        self.spawn_tracked(async move {
            let Some(mut rx) = lifecycle_network.subscribe_all_peer_events().await else {
                tracing::debug!(
                    "Peer lifecycle listener unavailable: network node not initialised"
                );
                return;
            };
            tracing::info!("Peer lifecycle watcher started for direct messaging");
            loop {
                let (peer_id, event) = tokio::select! {
                    _ = lifecycle_token.cancelled() => break,
                    recv = rx.recv() => match recv {
                        Ok(event) => event,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!("Peer lifecycle watcher lagged by {skipped} events");
                            continue;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    },
                };
                let machine_id = identity::MachineId(peer_id.0);
                match event {
                    ant_quic::PeerLifecycleEvent::Established { generation } => {
                        lifecycle_dm.record_lifecycle_established(machine_id, Some(generation));
                    }
                    ant_quic::PeerLifecycleEvent::Replaced { new_generation, .. } => {
                        lifecycle_dm.record_lifecycle_replaced(machine_id, new_generation);
                    }
                    ant_quic::PeerLifecycleEvent::Closing { generation, reason } => {
                        lifecycle_dm.record_lifecycle_blocked(
                            machine_id,
                            Some(generation),
                            format!("closing: {reason}"),
                        );
                    }
                    ant_quic::PeerLifecycleEvent::Closed { generation, reason } => {
                        lifecycle_dm.record_lifecycle_blocked(
                            machine_id,
                            Some(generation),
                            format!("closed: {reason}"),
                        );
                    }
                    ant_quic::PeerLifecycleEvent::ReaderExited { generation } => {
                        tracing::debug!(
                            machine_prefix = %network::hex_prefix(machine_id.as_bytes(), 4),
                            generation,
                            "peer reader exited; waiting for Closed/Established before blocking direct DM"
                        );
                    }
                }
            }
        });
    }

    /// Start the direct message listener background task.
    ///
    /// This task reads raw direct messages from the network layer and
    /// dispatches them to `DirectMessaging::handle_incoming()`, which
    /// fans out to all `subscribe_direct()` receiver queues.
    ///
    /// Called automatically by [`Agent::join_network`].
    fn start_direct_listener(&self) {
        if self
            .direct_listener_started
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }

        let Some(network) = self.network.as_ref().map(std::sync::Arc::clone) else {
            return;
        };
        let dm = std::sync::Arc::clone(&self.direct_messaging);
        let discovery_cache = std::sync::Arc::clone(&self.identity_discovery_cache);
        let contact_store = std::sync::Arc::clone(&self.contact_store);
        let revocation_set = std::sync::Arc::clone(&self.revocation_set);
        let token = self.shutdown_token.clone();

        self.spawn_tracked(async move {
            tracing::info!(target: "x0x::direct", stage = "listener", "direct message listener started");
            loop {
                // direct_tx is a NetworkNode struct field that outlives
                // network.shutdown(), so recv_direct() does not return None on
                // shutdown; the token is what stops this loop now.
                let recv = tokio::select! {
                    _ = token.cancelled() => break,
                    r = network.recv_direct() => r,
                };
                let Some((ant_peer_id, payload)) = recv else {
                    tracing::warn!(
                        target: "x0x::direct",
                        stage = "listener",
                        "network.recv_direct channel closed — listener exiting"
                    );
                    break;
                };

                let raw_bytes = payload.len();

                // Parse: first 32 bytes = sender AgentId, rest = payload
                if payload.len() < 32 {
                    tracing::warn!(
                        target: "x0x::direct",
                        stage = "listener",
                        machine_prefix = %crate::logging::LogTransportPeerId::from(&ant_peer_id),
                        raw_bytes,
                        outcome = "drop_too_short",
                        "direct message too short to contain sender id"
                    );
                    continue;
                }

                let mut sender_bytes = [0u8; 32];
                sender_bytes.copy_from_slice(&payload[..32]);
                let sender = identity::AgentId(sender_bytes);
                let machine_id = identity::MachineId(ant_peer_id.0);
                let data = payload[32..].to_vec();
                let payload_bytes = data.len();
                let digest = direct::dm_payload_digest_hex(&data);

                tracing::debug!(
                    target: "dm.trace",
                    stage = "inbound_envelope_received",
                    sender = %hex::encode(sender.as_bytes()),
                    machine_id = %hex::encode(machine_id.as_bytes()),
                    path = "raw_quic",
                    bytes = payload_bytes,
                    raw_bytes,
                    digest = %digest,
                );

                // Verify AgentId→MachineId binding against identity discovery cache.
                let (verified, cert_not_after) = {
                    let cache = discovery_cache.read().await;
                    cache
                        .get(&sender)
                        .map(|entry| (entry.machine_id == machine_id, entry.cert_not_after))
                        .unwrap_or((false, None))
                };

                // Evaluate trust for the (AgentId, MachineId) pair.
                let trust_decision = {
                    let contacts = contact_store.read().await;
                    let evaluator = trust::TrustEvaluator::new(&contacts);
                    let ctx = trust::TrustContext {
                        agent_id: &sender,
                        machine_id: &machine_id,
                    };
                    Some(evaluator.evaluate(&ctx))
                };

                tracing::debug!(
                    target: "dm.trace",
                    stage = "inbound_trust_evaluated",
                    sender = %hex::encode(sender.as_bytes()),
                    machine_id = %hex::encode(machine_id.as_bytes()),
                    path = "raw_quic",
                    verified,
                    decision = ?trust_decision,
                    digest = %digest,
                );

                tracing::info!(
                    target: "x0x::direct",
                    stage = "recv",
                    sender_prefix = %network::hex_prefix(&sender.0, 4),
                    machine_prefix = %network::hex_prefix(&machine_id.0, 4),
                    raw_bytes,
                    payload_bytes,
                    verified,
                    trust_decision = ?trust_decision,
                    "direct message received; dispatching to subscribers"
                );

                // Enforcement point — direct path revocation gate (issue #179).
                // Mirrors EP3 (dm_inbox) + the relay gate (peer_relay). EP5
                // (evict_revoked_subject) purges caches + sets trust=Blocked
                // but does NOT close the live QUIC connection, so without this
                // per-message check a revoked peer on an established direct
                // connection would keep delivering (annotated unverified, but
                // delivered). Fail closed: drop + count, never reach
                // mark_connected/handle_incoming. Read lock is held only for
                // the boolean — no await under it (same contract as EP4).
                let peer_revoked = {
                    let revoked = revocation_set.read().await;
                    direct::inbound_peer_revoked(&revoked, &sender, &machine_id)
                };
                if peer_revoked {
                    dm.record_incoming_dropped_revoked();
                    tracing::info!(
                        target: "x0x::direct",
                        stage = "recv",
                        sender_prefix = %network::hex_prefix(&sender.0, 4),
                        machine_prefix = %network::hex_prefix(&machine_id.0, 4),
                        outcome = "drop_revoked",
                        "direct message from revoked sender dropped (direct-path revocation gate, mirrors EP3)"
                    );
                    continue;
                }
                // Enforcement — runtime cert-expiry gate (issue #191). EP1
                // drops expired announcements at ingest, but a previously
                // cached entry is never re-checked on the live path; without
                // this an expired peer stays trusted until TTL eviction. Fail
                // closed: drop + count, mirroring the revoked EP above.
                // Absent expiry (None) is fail-open — is_expired returns false
                // for pre-#130 peers that carry no not_after.
                if identity::is_expired(cert_not_after, Agent::unix_timestamp_secs()) {
                    dm.record_incoming_dropped_expired();
                    tracing::info!(
                        target: "x0x::direct",
                        stage = "recv",
                        sender_prefix = %network::hex_prefix(&sender.0, 4),
                        machine_prefix = %network::hex_prefix(&machine_id.0, 4),
                        outcome = "drop_expired",
                        "direct message from sender with expired cert dropped (runtime expiry gate, issue #191)"
                    );
                    continue;
                }

                // Register and mark the sender as connected for future reverse direct sends.
                dm.mark_connected(sender, machine_id).await;

                // Fan out to all subscribe_direct() receivers with verification info.
                let delivered = dm
                    .handle_incoming(machine_id, sender, data, verified, trust_decision)
                    .await;

                tracing::debug!(
                    target: "dm.trace",
                    stage = "inbound_broadcast_published",
                    sender = %hex::encode(sender.as_bytes()),
                    machine_id = %hex::encode(machine_id.as_bytes()),
                    path = "raw_quic",
                    delivered,
                    subscribers = dm.subscriber_count(),
                    digest = %digest,
                );

                tracing::debug!(
                    target: "x0x::direct",
                    stage = "recv",
                    sender_prefix = %network::hex_prefix(&sender.0, 4),
                    payload_bytes,
                    subscriber_count = dm.subscriber_count(),
                    "direct message dispatched"
                );
            }
        });
    }

    // === Tailnet byte-streams (#132 T1) ===

    /// Open a bidirectional byte-stream to a verified, trusted peer.
    ///
    /// Resolves `agent_id` → machine via the identity discovery cache, then
    /// enforces the identity gate (verified binding → not revoked → trust
    /// `Accept`) before asking ant-quic to open the stream. The protocol
    /// prefix is written immediately after `open_bi` so the accept side can
    /// demux. Returns a [`streams::PeerStream`] ready for application I/O.
    pub async fn open_peer_stream(
        &self,
        agent_id: &identity::AgentId,
        protocol: streams::StreamProtocol,
    ) -> error::NetworkResult<streams::PeerStream> {
        let (machine_id, cert_not_after) = {
            let cache = self.identity_discovery_cache.read().await;
            cache
                .get(agent_id)
                .map(|entry| (entry.machine_id, entry.cert_not_after))
                .ok_or(error::NetworkError::PeerNotVerified {
                    agent_id: agent_id.0,
                })?
        };
        // Runtime cert-expiry gate (issue #191): EP1 drops expired
        // announcements at ingest but never re-checks a cached entry on the
        // live path. Absent expiry (None) is fail-open — is_expired returns
        // false, preserving compatibility with pre-#130 peers.
        let expired = identity::is_expired(cert_not_after, Self::unix_timestamp_secs());

        let trust_decision = {
            let contacts = self.contact_store.read().await;
            let evaluator = trust::TrustEvaluator::new(&contacts);
            Some(evaluator.evaluate(&trust::TrustContext {
                agent_id,
                machine_id: &machine_id,
            }))
        };
        let (revoked_agent, revoked_machine) = {
            let revoked = self.revocation_set.read().await;
            (
                revoked.is_agent_revoked(agent_id),
                revoked.is_machine_revoked(&machine_id),
            )
        };
        streams::stream_gate(
            agent_id,
            trust_decision,
            revoked_agent,
            revoked_machine,
            expired,
        )?;

        let network = self
            .network
            .as_ref()
            .ok_or_else(|| error::NetworkError::NodeError("network not initialized".to_string()))?;
        let peer = ant_quic::PeerId(machine_id.0);
        let (mut send, recv) = network.open_bi(&peer).await?;
        streams::write_protocol_prefix(&mut send, protocol).await?;
        tracing::info!(
            target: "x0x::streams",
            agent = %hex::encode(agent_id.as_bytes()),
            machine = %hex::encode(machine_id.as_bytes()),
            protocol = ?protocol,
            "outbound peer stream opened (identity gate cleared)"
        );
        Ok(streams::PeerStream::new(
            vec![*agent_id],
            machine_id,
            protocol,
            send,
            recv,
        ))
    }

    /// Await the next inbound byte-stream that has cleared the identity gate.
    ///
    /// Returns `None` when the accept loop has stopped (e.g. after shutdown).
    /// The T4 forwarder consumes accepted streams through this method.
    pub async fn next_incoming_stream(&self) -> Option<streams::PeerStream> {
        let mut rx = self.stream_accept.receiver().lock().await;
        rx.recv().await
    }

    /// Start the inbound byte-stream accept loop (idempotent).
    ///
    /// Called automatically by [`Agent::join_network`]. The loop is the SOLE
    /// consumer of [`network::NetworkNode::accept_bi`]; every inbound stream
    /// clears the identity gate (machine has a known agent → not revoked →
    /// trust `Accept`) and the protocol handshake before being surfaced via
    /// [`Self::next_incoming_stream`]. A stream that fails the gate is reset
    /// (its halves are dropped) with zero application bytes exchanged.
    fn start_stream_accept_loop(&self) {
        if !self.stream_accept.start_once() {
            return;
        }
        let Some(network) = self.network.as_ref().map(std::sync::Arc::clone) else {
            return;
        };
        let discovery_cache = std::sync::Arc::clone(&self.identity_discovery_cache);
        let contact_store = std::sync::Arc::clone(&self.contact_store);
        let revocation_set = std::sync::Arc::clone(&self.revocation_set);
        let incoming = std::sync::Arc::clone(&self.stream_accept);
        let token = self.shutdown_token.clone();

        self.spawn_tracked(async move {
            tracing::info!(target: "x0x::streams", "byte-stream accept loop started");
            loop {
                let accepted = tokio::select! {
                    _ = token.cancelled() => break,
                    r = network.accept_bi() => r,
                };
                let (ant_peer_id, send, mut recv) = match accepted {
                    Ok(triple) => triple,
                    Err(e) => {
                        tracing::warn!(target: "x0x::streams", error=%e, "accept_bi failed; continuing");
                        continue;
                    }
                };
                let machine_id = identity::MachineId(ant_peer_id.0);

                // Identity gate — resolve ALL agents on this machine from
                // the discovery cache, then check each (revoked → trust).
                // The QUIC transport authenticates the machine, not the
                // specific agent, so every agent on the machine must clear
                // the gate — a single revoked or untrusted agent denies the
                // stream (fail-closed, #192). Each lock is taken in its own
                // scope so no two identity locks are held at once
                // (evict_revoked_subject takes them in a different order).
                let agents: Vec<(identity::AgentId, Option<u64>)> = {
                    let cache = discovery_cache.read().await;
                    let mut found: Vec<(identity::AgentId, Option<u64>)> = cache
                        .values()
                        .filter(|a| a.machine_id == machine_id)
                        .map(|a| (a.agent_id, a.cert_not_after))
                        .collect();
                    // Deterministic order so logging / per-peer concurrency
                    // keying are stable across HashMap iteration orders.
                    found.sort_by_key(|(a, _)| a.0);
                    found
                };
                if agents.is_empty() {
                    tracing::info!(
                        target: "x0x::streams",
                        machine = %hex::encode(machine_id.as_bytes()),
                        outcome = "deny_not_verified",
                        "inbound stream from machine with no known agent — denied"
                    );
                    continue;
                }
                let now_secs = Agent::unix_timestamp_secs();
                let mut gate_denied: Option<(identity::AgentId, error::NetworkError)> = None;
                for (agent_id, cert_not_after) in &agents {
                    // Runtime cert-expiry gate (issue #191): a cached entry
                    // whose cert has expired must be refused on the live path.
                    let expired = identity::is_expired(*cert_not_after, now_secs);
                    let trust_decision = {
                        let contacts = contact_store.read().await;
                        let evaluator = trust::TrustEvaluator::new(&contacts);
                        Some(evaluator.evaluate(&trust::TrustContext {
                            agent_id,
                            machine_id: &machine_id,
                        }))
                    };
                    let (revoked_agent, revoked_machine) = {
                        let revoked = revocation_set.read().await;
                        (
                            revoked.is_agent_revoked(agent_id),
                            revoked.is_machine_revoked(&machine_id),
                        )
                    };
                    if let Err(e) = streams::stream_gate(
                        agent_id,
                        trust_decision,
                        revoked_agent,
                        revoked_machine,
                        expired,
                    ) {
                        gate_denied = Some((*agent_id, e));
                        break;
                    }
                }
                if let Some((agent_id, e)) = gate_denied {
                    tracing::info!(
                        target: "x0x::streams",
                        agent = %hex::encode(agent_id.as_bytes()),
                        machine = %hex::encode(machine_id.as_bytes()),
                        agent_count = agents.len(),
                        outcome = "deny_gate",
                        error = %e,
                        "inbound stream denied at identity gate (one agent on the machine failed)"
                    );
                    continue;
                }

                // Gate cleared for every agent — drop the expiry metadata and
                // keep the ordered agent list for the stream handle.
                let agents: Vec<identity::AgentId> =
                    agents.into_iter().map(|(a, _)| a).collect();

                // DISPATCH (DoS hardening, issue #132): the protocol-prefix
                // read + surfacing run in a per-stream task so a peer that
                // opens a stream and never sends the prefix cannot block this
                // accept loop (and thus every other peer's inbound streams).
                // The identity gate above already cleared; this task owns the
                // stream halves and drops them (→ QUIC reset) on any failure.
                let incoming_for_task = std::sync::Arc::clone(&incoming);
                tokio::spawn(async move {
                    // Belt-and-braces: bound the prefix read so a silent peer
                    // holds the task/stream for at most PREFIX_READ_TIMEOUT.
                    let protocol = match tokio::time::timeout(
                        streams::PREFIX_READ_TIMEOUT,
                        streams::read_protocol_prefix(&mut recv),
                    )
                    .await
                    {
                        Ok(Ok(p)) => p,
                        Ok(Err(e)) => {
                            tracing::info!(
                                target: "x0x::streams",
                                machine = %hex::encode(machine_id.as_bytes()),
                                outcome = "deny_protocol",
                                error = %e,
                                "inbound stream protocol prefix rejected"
                            );
                            return;
                        }
                        Err(_) => {
                            tracing::info!(
                                target: "x0x::streams",
                                machine = %hex::encode(machine_id.as_bytes()),
                                outcome = "deny_prefix_timeout",
                                "inbound stream prefix byte timed out — resetting"
                            );
                            return;
                        }
                    };
                    let peer_stream =
                        streams::PeerStream::new(agents, machine_id, protocol, send, recv);
                    // try_send so a slow consumer cannot pile up accepted
                    // streams in memory; a full channel drops the stream.
                    if incoming_for_task.sender().try_send(peer_stream).is_err() {
                        tracing::debug!(
                            target: "x0x::streams",
                            "incoming-stream channel full; dropping accepted stream"
                        );
                    }
                });
            }
        });
    }

    /// new announcement.
    ///
    /// Called automatically by [`Agent::join_network`].
    ///
    /// # Errors
    ///
    /// Returns an error if a required network or gossip component is missing.
    pub async fn start_identity_heartbeat(&self) -> error::Result<()> {
        let mut handle_guard = self.heartbeat_handle.lock().await;
        // Shutdown race (issue #116): a still-bootstrapping join_network can call
        // this after shutdown() began. Checking under the SAME lock that
        // stop_identity_heartbeat takes the handle from makes it TOCTOU-free:
        // stop_X runs after cancel(), so a handle stored before stop_X runs is
        // taken+aborted, and a store attempted after sees cancelled → refused.
        if self.shutdown_token.is_cancelled() {
            return Ok(());
        }
        if handle_guard.is_some() {
            return Ok(());
        }
        let Some(runtime) = self.gossip_runtime.as_ref().map(std::sync::Arc::clone) else {
            return Err(error::IdentityError::Storage(std::io::Error::other(
                "gossip runtime not initialized — cannot start heartbeat",
            )));
        };
        let Some(network) = self.network.as_ref().map(std::sync::Arc::clone) else {
            return Err(error::IdentityError::Storage(std::io::Error::other(
                "network not initialized — cannot start heartbeat",
            )));
        };
        let allow_local_discovery_addrs = allow_local_discovery_addresses(network.config());
        let ctx = HeartbeatContext {
            identity: std::sync::Arc::clone(&self.identity),
            runtime,
            network,
            interval_secs: self.heartbeat_interval_secs,
            cache: std::sync::Arc::clone(&self.identity_discovery_cache),
            machine_cache: std::sync::Arc::clone(&self.machine_discovery_cache),
            user_identity_consented: std::sync::Arc::clone(&self.user_identity_consented),
            allow_local_discovery_addrs,
            revocation_set: std::sync::Arc::clone(&self.revocation_set),
        };
        let handle = tokio::task::spawn(async move {
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(ctx.interval_secs));
            ticker.tick().await; // skip first immediate tick
            loop {
                ticker.tick().await;
                if let Err(e) = ctx.announce().await {
                    tracing::warn!("identity heartbeat announce failed: {e}");
                }
            }
        });
        *handle_guard = Some(handle);
        Ok(())
    }

    /// Publish a rendezvous `ProviderSummary` for this agent.
    ///
    /// Enables global findability across gossip overlay partitions.  Seekers
    /// that have never been on the same partition as this agent can still
    /// discover it by subscribing to the rendezvous shard topic and waiting
    /// for the next heartbeat advertisement.
    ///
    /// The summary is signed with this agent's machine key and contains the
    /// agent's reachability addresses in the `extensions` field (bincode-encoded
    /// `Vec<SocketAddr>`).
    ///
    /// # Re-advertisement contract
    ///
    /// Rendezvous summaries expire after `validity_ms` milliseconds.  **Callers
    /// are responsible for calling `advertise_identity` again before expiry** so
    /// that seekers can always find a fresh record.  A common strategy is to
    /// re-advertise every `validity_ms / 2`.  The `x0xd` daemon does this
    /// automatically via its background re-advertisement task.
    ///
    /// # Arguments
    ///
    /// * `validity_ms` — How long (milliseconds) before the summary expires.
    ///   After this time, seekers will no longer discover this agent via rendezvous
    ///   unless a fresh `advertise_identity` call is made.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized, serialization
    /// fails, or signing fails.
    pub async fn advertise_identity(&self, validity_ms: u64) -> error::Result<()> {
        use saorsa_gossip_rendezvous::{Capability, ProviderSummary};

        let runtime = self.gossip_runtime.as_ref().ok_or_else(|| {
            error::IdentityError::Storage(std::io::Error::other(
                "gossip runtime not initialized — cannot advertise identity",
            ))
        })?;

        let peer_id = runtime.peer_id();
        let addresses = self.announcement_addresses();
        let addr_bytes = bincode::serialize(&addresses).map_err(|e| {
            error::IdentityError::Serialization(format!(
                "failed to serialize addresses for rendezvous: {e}"
            ))
        })?;

        let mut summary = ProviderSummary::new(
            self.agent_id().0,
            peer_id,
            vec![Capability::Identity],
            validity_ms,
        )
        .with_extensions(addr_bytes);

        summary
            .sign_raw(self.identity.machine_keypair().secret_key().as_bytes())
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "failed to sign rendezvous summary: {e}"
                )))
            })?;

        let cbor_bytes = summary.to_cbor().map_err(|e| {
            error::IdentityError::Serialization(format!(
                "failed to CBOR-encode rendezvous summary: {e}"
            ))
        })?;

        let topic = rendezvous_shard_topic_for_agent(&self.agent_id());
        runtime
            .pubsub()
            .publish(topic, bytes::Bytes::from(cbor_bytes))
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "failed to publish rendezvous summary: {e}"
                )))
            })?;

        self.rendezvous_advertised
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Search for an agent via rendezvous shard subscription.
    ///
    /// Subscribes to the rendezvous shard topic for `agent_id` and waits up to
    /// `timeout_secs` for a matching [`saorsa_gossip_rendezvous::ProviderSummary`].
    /// On success the addresses encoded in the summary `extensions` field are
    /// returned.
    ///
    /// This is Stage 3 of [`Agent::find_agent`]'s lookup cascade.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn find_agent_rendezvous(
        &self,
        agent_id: identity::AgentId,
        timeout_secs: u64,
    ) -> error::Result<Option<Vec<std::net::SocketAddr>>> {
        use saorsa_gossip_rendezvous::ProviderSummary;

        let runtime = match self.gossip_runtime.as_ref() {
            Some(r) => r,
            None => return Ok(None),
        };

        let topic = rendezvous_shard_topic_for_agent(&agent_id);
        let mut sub = runtime.pubsub().subscribe(topic).await;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

        loop {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            tokio::select! {
                Some(msg) = sub.recv() => {
                    let summary = match ProviderSummary::from_cbor(&msg.payload) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    if summary.target != agent_id.0 {
                        continue;
                    }
                    // Verify the summary signature when the advertiser's machine
                    // public key is cached from a prior identity announcement.
                    // Without a cached key we still accept the addresses — they
                    // are connection hints only; the subsequent QUIC handshake will
                    // fail cryptographically if the endpoint is not the genuine agent.
                    let cached_pub = self
                        .identity_discovery_cache
                        .read()
                        .await
                        .get(&agent_id)
                        .map(|e| e.machine_public_key.clone());
                    if let Some(pub_bytes) = cached_pub {
                        if !pub_bytes.is_empty()
                            && !summary.verify_raw(&pub_bytes).unwrap_or(false)
                        {
                            tracing::warn!(
                                "Rendezvous summary signature verification failed for agent {:?}; discarding",
                                agent_id
                            );
                            continue;
                        }
                    }
                    // Decode addresses from the extensions field.
                    let addrs: Vec<std::net::SocketAddr> = summary
                        .extensions
                        .as_deref()
                        .and_then(|b| {
                            use bincode::Options;
                            bincode::DefaultOptions::new()
                                .with_fixint_encoding()
                                .with_limit(crate::network::MAX_MESSAGE_DESERIALIZE_SIZE)
                                .deserialize(b)
                                .ok()
                        })
                        .unwrap_or_default();
                    if !addrs.is_empty() {
                        return Ok(Some(addrs));
                    }
                }
                _ = tokio::time::sleep(remaining) => break,
            }
        }

        Ok(None)
    }

    /// Insert a discovered agent into the cache (for testing only).
    ///
    /// Insert a [`dm::DmCapabilities`] entry for `agent_id` / `machine_id`
    /// into the local capability store, bypassing the gossip-advert pipeline.
    ///
    /// # Visibility
    ///
    /// `#[doc(hidden)]` - tests-only seam. Production callers must rely on
    /// the live capability-advert subscription so the store mirrors what
    /// the network actually advertises.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Subject agent the capabilities apply to.
    /// * `machine_id` - Subject machine. Used by the store's lookup path
    ///   to disambiguate when an agent is reachable via multiple machines.
    /// * `capabilities` - The [`dm::DmCapabilities`] record (KEM public
    ///   key, gossip-inbox readiness, envelope-size cap, etc.) the sender
    ///   should treat as authoritative.
    #[doc(hidden)]
    pub fn insert_capability_for_testing(
        &self,
        agent_id: identity::AgentId,
        machine_id: identity::MachineId,
        capabilities: dm::DmCapabilities,
    ) {
        self.capability_store
            .insert(agent_id, machine_id, capabilities, dm::now_unix_ms());
    }

    /// # Arguments
    ///
    /// * `agent` - The agent entry to insert.
    #[doc(hidden)]
    pub async fn insert_discovered_agent_for_testing(&self, agent: DiscoveredAgent) {
        let agent_id = agent.agent_id;
        let machine_id = agent.machine_id;
        upsert_discovered_machine_from_agent(&self.machine_discovery_cache, &agent).await;
        upsert_discovered_agent(&self.identity_discovery_cache, agent).await;

        if machine_id.0 != [0u8; 32] {
            self.direct_messaging
                .register_agent(agent_id, machine_id)
                .await;
            if let Some(ref network) = self.network {
                let ant_peer_id = ant_quic::PeerId(machine_id.0);
                if network.is_connected(&ant_peer_id).await {
                    self.direct_messaging
                        .mark_connected(agent_id, machine_id)
                        .await;
                }
            }
        }
    }

    /// Test-only: mark `agent_id` as a `Trusted` contact so
    /// [`TrustEvaluator`] returns [`trust::TrustDecision::Accept`] for it.
    /// Used by the tailnet stream tests to clear the outbound/inbound trust
    /// gate without driving the full contact-import REST flow. The
    /// AgentId→MachineId *binding* still has to come from the discovery cache
    /// (see [`Self::insert_discovered_agent_for_testing`]).
    #[doc(hidden)]
    pub async fn set_contact_trusted_for_testing(&self, agent_id: identity::AgentId) {
        let mut store = self.contact_store.write().await;
        store.add(contacts::Contact {
            agent_id,
            trust_level: contacts::TrustLevel::Trusted,
            label: None,
            added_at: 0,
            last_seen: None,
            identity_type: contacts::IdentityType::Anonymous,
            machines: Vec::new(),
            dm_capabilities: None,
        });
    }

    /// Push a synthetic [`peer_relay::RelayedDm`] onto this Agent's inbound
    /// relay-DM channel, exactly as the wire demuxer would after receiving a
    /// [`network::RELAYED_DM_STREAM_TYPE`] frame. Drives the
    /// `spawn_relay_dm_listener` dispatch path (revocation gate →
    /// deliver-locally / forward / refuse) without a second live QUIC peer.
    ///
    /// `#[doc(hidden)]` - tests-only seam. The production inbound path is the
    /// network receiver task; this exists only because
    /// [`network::NetworkNode::send_direct_typed`] and the relay-DM channel
    /// sender are `pub(crate)`, so an out-of-crate integration test cannot
    /// otherwise exercise the recipient-side listener.
    ///
    /// # Arguments
    ///
    /// * `from_peer` - the QUIC peer the frame nominally arrived on (the
    ///   relay hop, or the origin for a self-addressed `RelayedDm`).
    /// * `relayed` - the fully-formed relayed envelope to dispatch.
    ///
    /// Returns `false` when no network is configured (nothing to receive on).
    #[doc(hidden)]
    pub async fn push_relayed_dm_for_testing(
        &self,
        from_peer: ant_quic::PeerId,
        relayed: peer_relay::RelayedDm,
    ) -> bool {
        let Some(ref network) = self.network else {
            return false;
        };
        let sender_agent_id = relayed.header.sender_agent_id;
        network
            .test_relayed_dm_sender()
            .send((from_peer, sender_agent_id, relayed))
            .await
            .is_ok()
    }

    /// Create a new collaborative task list bound to a topic.
    ///
    /// Creates a new `TaskList` and binds it to the specified gossip topic
    /// for automatic synchronization with other agents on the same topic.
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable name for the task list
    /// * `topic` - Gossip topic for synchronization
    ///
    /// # Returns
    ///
    /// A `TaskListHandle` for interacting with the task list.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let list = agent.create_task_list("Sprint Planning", "team-sprint").await?;
    /// ```
    pub async fn create_task_list(&self, name: &str, topic: &str) -> error::Result<TaskListHandle> {
        let runtime = self.gossip_runtime.as_ref().ok_or_else(|| {
            error::IdentityError::Storage(std::io::Error::other(
                "gossip runtime not initialized - configure agent with network first",
            ))
        })?;

        let peer_id = runtime.peer_id();
        let list_id = crdt::TaskListId::from_content(name, &self.agent_id(), 0);
        let task_list = crdt::TaskList::new(list_id, name.to_string(), peer_id);

        let sync = crdt::TaskListSync::new(
            task_list,
            std::sync::Arc::clone(runtime.pubsub()),
            topic.to_string(),
            peer_id,
        )
        .map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!(
                "task list sync creation failed: {}",
                e
            )))
        })?;

        let sync = std::sync::Arc::new(sync);
        sync.start_with_spawner(|fut| self.spawn_tracked(fut))
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "task list sync start failed: {}",
                    e
                )))
            })?;

        Ok(TaskListHandle {
            sync,
            agent_id: self.agent_id(),
            peer_id,
        })
    }

    /// Join an existing task list by topic.
    ///
    /// Connects to a task list that was created by another agent on the
    /// specified topic. The local replica will sync with peers automatically.
    ///
    /// # Arguments
    ///
    /// * `topic` - Gossip topic for the task list
    ///
    /// # Returns
    ///
    /// A `TaskListHandle` for interacting with the task list.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let list = agent.join_task_list("team-sprint").await?;
    /// ```
    pub async fn join_task_list(&self, topic: &str) -> error::Result<TaskListHandle> {
        let runtime = self.gossip_runtime.as_ref().ok_or_else(|| {
            error::IdentityError::Storage(std::io::Error::other(
                "gossip runtime not initialized - configure agent with network first",
            ))
        })?;

        let peer_id = runtime.peer_id();
        // Create empty task list; it will be populated via delta sync
        let list_id = crdt::TaskListId::from_content(topic, &self.agent_id(), 0);
        let task_list = crdt::TaskList::new(list_id, String::new(), peer_id);

        let sync = crdt::TaskListSync::new(
            task_list,
            std::sync::Arc::clone(runtime.pubsub()),
            topic.to_string(),
            peer_id,
        )
        .map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!(
                "task list sync creation failed: {}",
                e
            )))
        })?;

        let sync = std::sync::Arc::new(sync);
        sync.start_with_spawner(|fut| self.spawn_tracked(fut))
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "task list sync start failed: {}",
                    e
                )))
            })?;

        Ok(TaskListHandle {
            sync,
            agent_id: self.agent_id(),
            peer_id,
        })
    }
}

impl AgentBuilder {
    /// Set a custom path for the machine keypair.
    ///
    /// If not set, the machine keypair is stored in `~/.x0x/machine.key`.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to store the machine keypair.
    ///
    /// # Returns
    ///
    /// Self for chaining.
    pub fn with_machine_key<P: AsRef<std::path::Path>>(mut self, path: P) -> Self {
        self.machine_key_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Import an agent keypair.
    ///
    /// If not set, the agent keypair is loaded from storage (or generated fresh
    /// if no stored key exists).
    ///
    /// This enables running the same agent on multiple machines by importing
    /// the same agent keypair (but with different machine keypairs).
    ///
    /// Note: When an explicit keypair is provided via this method, it takes
    /// precedence over `with_agent_key_path()`.
    ///
    /// # Arguments
    ///
    /// * `keypair` - The agent keypair to import.
    ///
    /// # Returns
    ///
    /// Self for chaining.
    pub fn with_agent_key(mut self, keypair: identity::AgentKeypair) -> Self {
        self.agent_keypair = Some(keypair);
        self
    }

    /// Set a custom path for the agent keypair.
    ///
    /// If not set, the agent keypair is stored in `~/.x0x/agent.key`.
    /// If no stored key is found at the path, a fresh one is generated and saved.
    ///
    /// This is ignored when `with_agent_key()` provides an explicit keypair.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to store/load the agent keypair.
    ///
    /// # Returns
    ///
    /// Self for chaining.
    pub fn with_agent_key_path<P: AsRef<std::path::Path>>(mut self, path: P) -> Self {
        self.agent_key_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set a custom path for the agent certificate (`agent.cert`).
    ///
    /// Required for multi-daemon setups that share a host — the default
    /// path (`~/.x0x/agent.cert`) is shared across daemons, causing
    /// last-writer-wins trampling that makes peers reject identity
    /// announcements as `agent certificate agent_id mismatch`.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to use for the agent certificate file.
    ///
    /// # Returns
    ///
    /// Self for chaining.
    #[must_use]
    pub fn with_agent_cert_path<P: AsRef<std::path::Path>>(mut self, path: P) -> Self {
        self.agent_cert_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set network configuration for P2P communication.
    ///
    /// If not set, the agent is built without a network node or gossip
    /// runtime. Use `NetworkConfig::default()` to connect through the default
    /// bootstrap nodes.
    ///
    /// # Arguments
    ///
    /// * `config` - The network configuration to use.
    ///
    /// # Returns
    ///
    /// Self for chaining.
    pub fn with_network_config(mut self, config: network::NetworkConfig) -> Self {
        self.network_config = Some(config);
        self
    }

    /// Set gossip overlay configuration.
    ///
    /// This is primarily used by x0xd to expose operational knobs such as
    /// `gossip.dispatch_workers`. If the agent is built without a network
    /// configuration, the value is retained by the builder but has no runtime
    /// effect.
    #[must_use]
    pub fn with_gossip_config(mut self, config: gossip::GossipConfig) -> Self {
        self.gossip_config = Some(config);
        self
    }

    /// Set the directory for the bootstrap peer cache.
    ///
    /// The cache persists peer quality metrics across restarts, enabling
    /// cache-first join strategy. Defaults to `~/.x0x/peers/` if not set.
    /// Falls back to `./.x0x/peers/` (relative to CWD) if `$HOME` is unset.
    pub fn with_peer_cache_dir<P: AsRef<std::path::Path>>(mut self, path: P) -> Self {
        self.peer_cache_dir = Some(path.as_ref().to_path_buf());
        self
    }

    /// Disable the bootstrap peer cache entirely.
    ///
    /// When set, the agent will not open or load any cached peers on
    /// startup. This ensures complete network isolation from previously
    /// seen peers for embedders and dedicated test harnesses.
    ///
    /// Note: the x0xd daemon's `--no-hard-coded-bootstrap` flag does
    /// not call this; it only clears configured seed peers.
    pub fn with_peer_cache_disabled(mut self) -> Self {
        self.disable_peer_cache = true;
        self
    }

    /// Import a user keypair for three-layer identity.
    ///
    /// This binds a human identity to this agent. When provided, an
    /// [`identity::AgentCertificate`] is automatically issued (if one
    /// doesn't already exist in storage) to cryptographically attest
    /// that this agent belongs to the user.
    ///
    /// Note: When an explicit keypair is provided via this method, it takes
    /// precedence over `with_user_key_path()`.
    ///
    /// # Arguments
    ///
    /// * `keypair` - The user keypair to import.
    ///
    /// # Returns
    ///
    /// Self for chaining.
    pub fn with_user_key(mut self, keypair: identity::UserKeypair) -> Self {
        self.user_keypair = Some(keypair);
        self
    }

    /// Set a custom path for the user keypair.
    ///
    /// Unlike machine and agent keys, user keys are **not** auto-generated.
    /// If the file at this path doesn't exist, no user identity is set
    /// (the agent operates with two-layer identity).
    ///
    /// This is ignored when `with_user_key()` provides an explicit keypair.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to load the user keypair from.
    ///
    /// # Returns
    ///
    /// Self for chaining.
    pub fn with_user_key_path<P: AsRef<std::path::Path>>(mut self, path: P) -> Self {
        self.user_key_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set the identity heartbeat re-announcement interval.
    ///
    /// Defaults to [`IDENTITY_HEARTBEAT_INTERVAL_SECS`] (300 seconds).
    ///
    /// # Arguments
    ///
    /// * `secs` - Interval in seconds between identity re-announcements.
    #[must_use]
    pub fn with_heartbeat_interval(mut self, secs: u64) -> Self {
        self.heartbeat_interval_secs = Some(secs);
        self
    }

    /// Set the identity cache TTL.
    ///
    /// Cache entries with `last_seen` older than this threshold are filtered
    /// from [`Agent::presence`] and [`Agent::discovered_agents`].
    ///
    /// Defaults to [`IDENTITY_TTL_SECS`] (900 seconds).
    ///
    /// # Arguments
    ///
    /// * `secs` - Time-to-live in seconds for discovered agent entries.
    #[must_use]
    pub fn with_identity_ttl(mut self, secs: u64) -> Self {
        self.identity_ttl_secs = Some(secs);
        self
    }

    /// Override the presence beacon broadcast interval in seconds.
    #[must_use]
    pub fn with_presence_beacon_interval(mut self, secs: u64) -> Self {
        self.presence_beacon_interval_secs = Some(secs);
        self
    }

    /// Override the presence event poll interval in seconds.
    #[must_use]
    pub fn with_presence_event_poll_interval(mut self, secs: u64) -> Self {
        self.presence_event_poll_interval_secs = Some(secs);
        self
    }

    /// Override the fallback offline timeout used by presence events.
    #[must_use]
    pub fn with_presence_offline_timeout(mut self, secs: u64) -> Self {
        self.presence_offline_timeout_secs = Some(secs);
        self
    }

    /// Set a custom path for the contacts file.
    ///
    /// The contacts file persists trust levels and machine records for known
    /// agents. Defaults to `~/.x0x/contacts.json` if not set.
    ///
    /// # Arguments
    ///
    /// * `path` - The path for the contacts file.
    #[must_use]
    pub fn with_contact_store_path<P: AsRef<std::path::Path>>(mut self, path: P) -> Self {
        self.contact_store_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set the directory used for all identity-scoped files (keys, certificate,
    /// and the revocation set `revocations.bin`).
    ///
    /// When set, the revocation set is loaded from / saved to
    /// `<identity_dir>/revocations.bin` instead of `~/.x0x/revocations.bin`.
    /// This mirrors how `with_machine_key`, `with_agent_key_path`, and
    /// `with_agent_cert_path` scope their respective files.
    ///
    /// Callers that already configure all three key paths individually do not
    /// need to set this — it is primarily a convenience for the x0xd server
    /// which builds the agent with an explicit identity directory.
    #[must_use]
    pub fn with_identity_dir<P: AsRef<std::path::Path>>(mut self, path: P) -> Self {
        self.identity_dir = Some(path.as_ref().to_path_buf());
        self
    }

    /// Build and initialise the agent.
    ///
    /// This performs the following:
    /// 1. Loads or generates the machine keypair (stored in `~/.x0x/machine.key` by default)
    /// 2. Uses provided agent keypair or generates a fresh one
    /// 3. Combines both into a unified Identity
    ///
    /// The machine keypair is automatically persisted to storage.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Machine keypair generation fails
    /// - Storage I/O fails
    /// - Keypair deserialization fails
    pub async fn build(self) -> error::Result<Agent> {
        // Determine machine keypair source
        let machine_keypair = if let Some(path) = self.machine_key_path {
            // Try to load from custom path
            match storage::load_machine_keypair_from(&path).await {
                Ok(kp) => kp,
                Err(_) => {
                    // Generate fresh keypair and save to custom path
                    let kp = identity::MachineKeypair::generate()?;
                    storage::save_machine_keypair_to(&kp, &path).await?;
                    kp
                }
            }
        } else if storage::machine_keypair_exists().await {
            // Load default machine keypair
            storage::load_machine_keypair().await?
        } else {
            // Generate and save default machine keypair
            let kp = identity::MachineKeypair::generate()?;
            storage::save_machine_keypair(&kp).await?;
            kp
        };

        // Resolve agent keypair: explicit > path-based > default storage > generate
        let agent_keypair = if let Some(kp) = self.agent_keypair {
            // Explicit keypair takes highest precedence
            kp
        } else if let Some(path) = self.agent_key_path {
            // Custom path: load or generate+save
            match storage::load_agent_keypair_from(&path).await {
                Ok(kp) => kp,
                Err(_) => {
                    let kp = identity::AgentKeypair::generate()?;
                    storage::save_agent_keypair_to(&kp, &path).await?;
                    kp
                }
            }
        } else if storage::agent_keypair_exists().await {
            // Default path exists: load it
            storage::load_agent_keypair_default().await?
        } else {
            // No stored key: generate and persist
            let kp = identity::AgentKeypair::generate()?;
            storage::save_agent_keypair_default(&kp).await?;
            kp
        };

        // Resolve user keypair: explicit > path-based > default storage > None (opt-in)
        let user_keypair = if let Some(kp) = self.user_keypair {
            Some(kp)
        } else if let Some(path) = self.user_key_path {
            // Custom path: load if exists, otherwise None (don't auto-generate)
            storage::load_user_keypair_from(&path).await.ok()
        } else if storage::user_keypair_exists().await {
            // Default path exists: load it
            storage::load_user_keypair().await.ok()
        } else {
            None
        };

        // Build identity with optional user layer.
        //
        // The agent certificate binds (user_id, agent_id). On load we must
        // verify BOTH halves of the binding match the current identity —
        // user_id AND agent_id — and re-issue if either diverges. A mismatch
        // happens in two practical scenarios:
        //   1. The user key was replaced (cert's user_id no longer ours).
        //   2. Multi-daemon-per-host setups where the cert path is shared
        //      and a peer daemon overwrote it with their own cert (cert's
        //      agent_id no longer ours).
        // Without the agent_id half of the check, scenario (2) produces an
        // announcement whose cert binds another daemon's agent_id, and peers
        // reject it as "agent certificate agent_id mismatch".
        //
        // The per-daemon `agent_cert_path` (set by `with_agent_cert_path()`)
        // is the structural fix for scenario (2); the agent_id check is the
        // defensive net in case two processes still land on the same path.
        let identity = if let Some(user_kp) = user_keypair {
            let cert_path = self.agent_cert_path.clone();
            let existing_cert = if let Some(ref p) = cert_path {
                if tokio::fs::try_exists(p).await.unwrap_or(false) {
                    storage::load_agent_certificate_from(p).await.ok()
                } else {
                    None
                }
            } else if storage::agent_certificate_exists().await {
                storage::load_agent_certificate().await.ok()
            } else {
                None
            };

            let cert_still_valid = existing_cert.as_ref().is_some_and(|c| {
                let user_match = c
                    .user_id()
                    .map(|uid| uid == user_kp.user_id())
                    .unwrap_or(false);
                let agent_match = c
                    .agent_id()
                    .map(|aid| aid == agent_keypair.agent_id())
                    .unwrap_or(false);
                user_match && agent_match
            });

            let cert = if cert_still_valid {
                existing_cert.ok_or_else(|| {
                    error::IdentityError::Storage(std::io::Error::other(
                        "agent certificate validity check succeeded with no certificate loaded",
                    ))
                })?
            } else {
                let new_cert = identity::AgentCertificate::issue(&user_kp, &agent_keypair)?;
                if let Some(ref p) = cert_path {
                    storage::save_agent_certificate_to(&new_cert, p).await?;
                } else {
                    storage::save_agent_certificate(&new_cert).await?;
                }
                new_cert
            };
            identity::Identity::new_with_user(machine_keypair, agent_keypair, user_kp, cert)
        } else {
            identity::Identity::new(machine_keypair, agent_keypair)
        };

        // Open bootstrap peer cache if network will be configured
        // and the cache is not explicitly disabled by the caller.
        let bootstrap_cache = if self.network_config.is_some() && !self.disable_peer_cache {
            let cache_dir = self.peer_cache_dir.unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join(".x0x")
                    .join("peers")
            });
            let config = ant_quic::BootstrapCacheConfig::builder()
                .cache_dir(cache_dir)
                .min_peers_to_save(1)
                .build();
            match ant_quic::BootstrapCache::open(config).await {
                Ok(cache) => {
                    let cache = std::sync::Arc::new(cache);
                    std::sync::Arc::clone(&cache).start_maintenance();
                    Some(cache)
                }
                Err(e) => {
                    tracing::warn!("Failed to open bootstrap cache: {e}");
                    None
                }
            }
        } else {
            None
        };

        // Create network node if configured
        // Pass the machine keypair so ant-quic PeerId == MachineId (identity unification)
        let machine_keypair = {
            let pk = ant_quic::MlDsaPublicKey::from_bytes(
                identity.machine_keypair().public_key().as_bytes(),
            )
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "invalid machine public key: {e}"
                )))
            })?;
            let sk = ant_quic::MlDsaSecretKey::from_bytes(
                identity.machine_keypair().secret_key().as_bytes(),
            )
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "invalid machine secret key: {e}"
                )))
            })?;
            Some((pk, sk))
        };

        // X0X-0070b: extract the relay policy + seed candidate list before
        // `self.network_config` is moved into `NetworkNode::new`. With no
        // network config the relay engine is built from `PeerRelayConfig::default()`,
        // which is `enabled = false` - the engine is then inert.
        let peer_relay_config = self
            .network_config
            .as_ref()
            .map(|cfg| cfg.peer_relay.clone())
            .unwrap_or_default();
        let mut parsed_relay_candidates = Vec::with_capacity(peer_relay_config.candidates.len());
        for hex_str in &peer_relay_config.candidates {
            let trimmed = hex_str.trim();
            let bytes = hex::decode(trimmed).map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "invalid relay candidate hex {trimmed:?}: {e}"
                )))
            })?;
            let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "relay candidate must be 32 bytes (got {} bytes)",
                    v.len()
                )))
            })?;
            parsed_relay_candidates.push(identity::AgentId(arr));
        }
        let peer_relay = std::sync::Arc::new(peer_relay::PeerRelay::with_policy(
            peer_relay_config.to_policy(),
        ));
        let relay_candidates =
            std::sync::Arc::new(tokio::sync::RwLock::new(parsed_relay_candidates));

        // X0X-0070b: discovery cache is hoisted out of the `Agent` literal so
        // the relay-DM listener (spawned below) can hold an `Arc` clone of it
        // without going through `&self` - the listener is a sibling task to
        // the network receiver, not an `Agent` method.
        let identity_discovery_cache: std::sync::Arc<
            tokio::sync::RwLock<std::collections::HashMap<identity::AgentId, DiscoveredAgent>>,
        > = std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));

        let network = if let Some(config) = self.network_config {
            let node = network::NetworkNode::new(config, bootstrap_cache.clone(), machine_keypair)
                .await
                .map_err(|e| {
                    error::IdentityError::Storage(std::io::Error::other(format!(
                        "network initialization failed: {}",
                        e
                    )))
                })?;

            // Verify identity unification: ant-quic PeerId must equal MachineId
            debug_assert_eq!(
                node.peer_id().0,
                identity.machine_id().0,
                "ant-quic PeerId must equal MachineId after identity unification"
            );

            Some(std::sync::Arc::new(node))
        } else {
            None
        };

        // Load the local revocation set now (shared Arc) so the relay-DM
        // listener can enforce revocation on inbound relayed envelopes. The
        // same Arc is moved into the Agent below, so the listener and the
        // Agent's `/identity/revoke` writes observe one shared set.
        let revocation_set = std::sync::Arc::new(tokio::sync::RwLock::new(
            storage::load_revocation_set(self.identity_dir.as_deref()).await,
        ));

        // Initialise contact store now (hoisted before the relay-DM
        // listener spawn so the listener can resolve the #193 contact
        // gate against the same shared store the Agent mutates).
        let contacts_path = self.contact_store_path.unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".x0x")
                .join("contacts.json")
        });
        let contact_store = std::sync::Arc::new(tokio::sync::RwLock::new(
            contacts::ContactStore::new(contacts_path),
        ));

        // X0X-0070b: spawn the inbound RelayedDm listener so this Agent can
        // serve as either the final recipient (DeliverLocally) or the
        // intermediate relay (Forward) for peers that fell back to the
        // relay path. Only meaningful when a network is configured -
        // without one there is nothing to receive on and nothing to
        // forward to.
        if let Some(ref net) = network {
            spawn_relay_dm_listener(
                std::sync::Arc::clone(net),
                std::sync::Arc::clone(&peer_relay),
                std::sync::Arc::clone(&identity_discovery_cache),
                std::sync::Arc::clone(&revocation_set),
                std::sync::Arc::clone(&contact_store),
                identity.agent_id(),
            );
        }

        // Create signing context from agent keypair for message authentication
        let signing_ctx = std::sync::Arc::new(gossip::SigningContext::from_keypair(
            identity.agent_keypair(),
        ));

        // Create gossip runtime if network exists
        let gossip_runtime = if let Some(ref net) = network {
            let runtime = gossip::GossipRuntime::new(
                self.gossip_config.unwrap_or_default(),
                std::sync::Arc::clone(net),
                Some(signing_ctx),
            )
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "gossip runtime initialization failed: {}",
                    e
                )))
            })?;
            Some(std::sync::Arc::new(runtime))
        } else {
            None
        };

        // Wrap bootstrap cache with gossip coordinator adapter (zero duplication).
        let gossip_cache_adapter = bootstrap_cache.as_ref().map(|cache| {
            saorsa_gossip_coordinator::GossipCacheAdapter::new(std::sync::Arc::clone(cache))
        });

        // Initialize direct messaging infrastructure
        let direct_messaging = std::sync::Arc::new(direct::DirectMessaging::new());

        // Create presence wrapper if network exists
        let presence = if let Some(ref net) = network {
            let peer_id = saorsa_gossip_transport::GossipTransport::local_peer_id(net.as_ref());
            let mut presence_config = presence::PresenceConfig::default();
            if let Some(secs) = self.presence_beacon_interval_secs {
                presence_config.beacon_interval_secs = secs;
            }
            if let Some(secs) = self.presence_event_poll_interval_secs {
                presence_config.event_poll_interval_secs = secs;
            }
            if let Some(secs) = self.presence_offline_timeout_secs {
                presence_config.adaptive_timeout_fallback_secs = secs;
            }
            // Sign presence beacons with the machine keypair that backs
            // `peer_id` (= net.local_peer_id()). The presence layer binds the
            // signer key to the claimed sender, so a beacon signed by any
            // other key would be rejected by every receiver (including this
            // node's own loopback path).
            let pw = presence::PresenceWrapper::new(
                peer_id,
                identity.machine_keypair().to_bytes(),
                std::sync::Arc::clone(net),
                presence_config,
                bootstrap_cache.clone(),
            )
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "presence initialization failed: {}",
                    e
                )))
            })?;
            let pw_arc = std::sync::Arc::new(pw);
            // Wire presence into gossip runtime for Bulk dispatch
            if let Some(ref rt) = gossip_runtime {
                rt.set_presence(std::sync::Arc::clone(&pw_arc));
            }
            Some(pw_arc)
        } else {
            None
        };

        // Load the revocation set from disk so enforcement takes effect
        // immediately on restart, even before the next gossip heartbeat.
        Ok(Agent {
            identity: std::sync::Arc::new(identity),
            network,
            gossip_runtime,
            bootstrap_cache,
            gossip_cache_adapter,
            identity_discovery_cache,
            machine_discovery_cache: std::sync::Arc::new(tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            user_discovery_cache: std::sync::Arc::new(tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            identity_listener_started: std::sync::atomic::AtomicBool::new(false),
            heartbeat_interval_secs: self
                .heartbeat_interval_secs
                .unwrap_or(IDENTITY_HEARTBEAT_INTERVAL_SECS),
            identity_ttl_secs: self.identity_ttl_secs.unwrap_or(IDENTITY_TTL_SECS),
            heartbeat_handle: tokio::sync::Mutex::new(None),
            discovery_cache_reaper_handle: tokio::sync::Mutex::new(None),
            rendezvous_advertised: std::sync::atomic::AtomicBool::new(false),
            contact_store,
            direct_messaging,
            network_event_listener_started: std::sync::atomic::AtomicBool::new(false),
            direct_listener_started: std::sync::atomic::AtomicBool::new(false),
            presence,
            user_identity_consented: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            capability_store: std::sync::Arc::new(dm_capability::CapabilityStore::new()),
            dm_capabilities_tx: std::sync::Arc::new({
                let (tx, _rx) = tokio::sync::watch::channel(dm::DmCapabilities::pending());
                tx
            }),
            dm_inflight_acks: std::sync::Arc::new(dm::InFlightAcks::new()),
            recent_delivery_cache: std::sync::Arc::new(dm::RecentDeliveryCache::with_defaults()),
            capability_advert_service: tokio::sync::Mutex::new(None),
            dm_inbox_service: tokio::sync::Mutex::new(None),
            revocation_set,
            identity_dir: self.identity_dir,
            shutdown_token: tokio_util::sync::CancellationToken::new(),
            tracked_tasks: std::sync::Arc::new(std::sync::Mutex::new(TrackedTasks {
                closed: false,
                handles: Vec::new(),
            })),
            peer_relay,
            relay_candidates,
            stream_accept: std::sync::Arc::new(streams::StreamAccept::new(256)),
        })
    }
}

/// Handle for interacting with a collaborative task list.
///
/// Provides a safe, concurrent interface to a TaskList backed by
/// CRDT synchronization. All operations are async and return Results.
///
/// # Example
///
/// ```ignore
/// let handle = agent.create_task_list("My List", "topic").await?;
/// let task_id = handle.add_task("Write docs".to_string(), "API docs".to_string()).await?;
/// handle.claim_task(task_id).await?;
/// handle.complete_task(task_id).await?;
/// ```
#[derive(Clone)]
pub struct TaskListHandle {
    sync: std::sync::Arc<crdt::TaskListSync>,
    agent_id: identity::AgentId,
    peer_id: saorsa_gossip_types::PeerId,
}

impl std::fmt::Debug for TaskListHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskListHandle")
            .field("agent_id", &self.agent_id)
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

impl TaskListHandle {
    /// Add a new task to the list.
    ///
    /// # Arguments
    ///
    /// * `title` - Task title
    /// * `description` - Task description
    ///
    /// # Returns
    ///
    /// The TaskId of the created task.
    ///
    /// # Errors
    ///
    /// Returns an error if the task cannot be added.
    pub async fn add_task(
        &self,
        title: String,
        description: String,
    ) -> error::Result<crdt::TaskId> {
        let (task_id, delta) = {
            let mut list = self.sync.write().await;
            let seq = list.next_seq();
            let task_id = crdt::TaskId::new(&title, &self.agent_id, seq);
            let metadata = crdt::TaskMetadata::new(title, description, 128, self.agent_id, seq);
            let task = crdt::TaskItem::new(task_id, metadata, self.peer_id);
            list.add_task(task.clone(), self.peer_id, seq)
                .map_err(|e| {
                    error::IdentityError::Storage(std::io::Error::other(format!(
                        "add_task failed: {}",
                        e
                    )))
                })?;
            let tag = (self.peer_id, seq);
            let delta = crdt::TaskListDelta::for_add(task_id, task, tag, list.current_version());
            (task_id, delta)
        };
        // Best-effort replication: local mutation succeeded regardless
        if let Err(e) = self.sync.publish_delta(self.peer_id, delta).await {
            tracing::warn!("failed to publish add_task delta: {}", e);
        }
        Ok(task_id)
    }

    /// Claim a task in the list.
    ///
    /// # Arguments
    ///
    /// * `task_id` - ID of the task to claim
    ///
    /// # Errors
    ///
    /// Returns an error if the task cannot be claimed.
    pub async fn claim_task(&self, task_id: crdt::TaskId) -> error::Result<()> {
        let delta = {
            let mut list = self.sync.write().await;
            let seq = list.next_seq();
            list.claim_task(&task_id, self.agent_id, self.peer_id, seq)
                .map_err(|e| {
                    error::IdentityError::Storage(std::io::Error::other(format!(
                        "claim_task failed: {}",
                        e
                    )))
                })?;
            // Include full task so receivers can upsert if add hasn't arrived yet
            let full_task = list
                .get_task(&task_id)
                .ok_or_else(|| {
                    error::IdentityError::Storage(std::io::Error::other(
                        "task disappeared after claim",
                    ))
                })?
                .clone();
            crdt::TaskListDelta::for_state_change(task_id, full_task, list.current_version())
        };
        if let Err(e) = self.sync.publish_delta(self.peer_id, delta).await {
            tracing::warn!("failed to publish claim_task delta: {}", e);
        }
        Ok(())
    }

    /// Complete a task in the list.
    ///
    /// # Arguments
    ///
    /// * `task_id` - ID of the task to complete
    ///
    /// # Errors
    ///
    /// Returns an error if the task cannot be completed.
    pub async fn complete_task(&self, task_id: crdt::TaskId) -> error::Result<()> {
        let delta = {
            let mut list = self.sync.write().await;
            let seq = list.next_seq();
            list.complete_task(&task_id, self.agent_id, self.peer_id, seq)
                .map_err(|e| {
                    error::IdentityError::Storage(std::io::Error::other(format!(
                        "complete_task failed: {}",
                        e
                    )))
                })?;
            let full_task = list
                .get_task(&task_id)
                .ok_or_else(|| {
                    error::IdentityError::Storage(std::io::Error::other(
                        "task disappeared after complete",
                    ))
                })?
                .clone();
            crdt::TaskListDelta::for_state_change(task_id, full_task, list.current_version())
        };
        if let Err(e) = self.sync.publish_delta(self.peer_id, delta).await {
            tracing::warn!("failed to publish complete_task delta: {}", e);
        }
        Ok(())
    }

    /// List all tasks in their current order.
    ///
    /// # Returns
    ///
    /// A vector of `TaskSnapshot` representing the current state.
    ///
    /// # Errors
    ///
    /// Returns an error if the task list cannot be read.
    pub async fn list_tasks(&self) -> error::Result<Vec<TaskSnapshot>> {
        let list = self.sync.read().await;
        let tasks = list.tasks_ordered();
        Ok(tasks
            .into_iter()
            .map(|task| TaskSnapshot {
                id: *task.id(),
                title: task.title().to_string(),
                description: task.description().to_string(),
                state: task.current_state(),
                assignee: task.assignee().copied(),
                owner: None,
                priority: task.priority(),
            })
            .collect())
    }

    /// Reorder tasks in the list.
    ///
    /// # Arguments
    ///
    /// * `task_ids` - New ordering of task IDs
    ///
    /// # Errors
    ///
    /// Returns an error if reordering fails.
    pub async fn reorder(&self, task_ids: Vec<crdt::TaskId>) -> error::Result<()> {
        let delta = {
            let mut list = self.sync.write().await;
            list.reorder(task_ids.clone(), self.peer_id).map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "reorder failed: {}",
                    e
                )))
            })?;
            // Carry the post-reorder ordering register (value + clock) so the
            // change merges by causality on receivers.
            crdt::TaskListDelta::for_reorder(
                list.ordering_register().clone(),
                list.current_version(),
            )
        };
        if let Err(e) = self.sync.publish_delta(self.peer_id, delta).await {
            tracing::warn!("failed to publish reorder delta: {}", e);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// KvStore API
// ---------------------------------------------------------------------------

impl Agent {
    /// Create a new key-value store.
    ///
    /// The store is automatically synchronized to all peers subscribed
    /// to the same `topic` via gossip delta propagation.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn create_kv_store(&self, name: &str, topic: &str) -> error::Result<KvStoreHandle> {
        let runtime = self.gossip_runtime.as_ref().ok_or_else(|| {
            error::IdentityError::Storage(std::io::Error::other(
                "gossip runtime not initialized - configure agent with network first",
            ))
        })?;

        let peer_id = runtime.peer_id();
        let store_id = kv::KvStoreId::from_content(name, &self.agent_id());
        let store = kv::KvStore::new(
            store_id,
            name.to_string(),
            self.agent_id(),
            kv::AccessPolicy::Signed,
        );

        let sync = kv::KvStoreSync::new(
            store,
            std::sync::Arc::clone(runtime.pubsub()),
            topic.to_string(),
            peer_id,
        )
        .map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!(
                "kv store sync creation failed: {e}",
            )))
        })?;

        let sync = std::sync::Arc::new(sync);
        sync.start_with_spawner(|fut| self.spawn_tracked(fut))
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "kv store sync start failed: {e}",
                )))
            })?;

        Ok(KvStoreHandle {
            sync,
            agent_id: self.agent_id(),
            peer_id,
        })
    }

    /// Join an existing key-value store by topic.
    ///
    /// Creates an empty store that will be populated via delta sync
    /// from peers already sharing the topic. The access policy will
    /// be learned from the first full delta received from the owner.
    ///
    /// # Errors
    ///
    /// Returns an error if the gossip runtime is not initialized.
    pub async fn join_kv_store(&self, topic: &str) -> error::Result<KvStoreHandle> {
        let runtime = self.gossip_runtime.as_ref().ok_or_else(|| {
            error::IdentityError::Storage(std::io::Error::other(
                "gossip runtime not initialized - configure agent with network first",
            ))
        })?;

        let peer_id = runtime.peer_id();
        let store_id = kv::KvStoreId::from_content(topic, &self.agent_id());
        // Use Encrypted as the most permissive default — the actual policy
        // will be set when the first delta from the owner arrives.
        let store = kv::KvStore::new(
            store_id,
            String::new(),
            self.agent_id(),
            kv::AccessPolicy::Encrypted {
                group_id: Vec::new(),
            },
        );

        let sync = kv::KvStoreSync::new(
            store,
            std::sync::Arc::clone(runtime.pubsub()),
            topic.to_string(),
            peer_id,
        )
        .map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!(
                "kv store sync creation failed: {e}",
            )))
        })?;

        let sync = std::sync::Arc::new(sync);
        sync.start_with_spawner(|fut| self.spawn_tracked(fut))
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "kv store sync start failed: {e}",
                )))
            })?;

        Ok(KvStoreHandle {
            sync,
            agent_id: self.agent_id(),
            peer_id,
        })
    }
}

/// Handle for interacting with a replicated key-value store.
///
/// Provides async methods for putting, getting, and removing entries.
/// Changes are automatically replicated to peers via gossip.
#[derive(Clone)]
pub struct KvStoreHandle {
    sync: std::sync::Arc<kv::KvStoreSync>,
    agent_id: identity::AgentId,
    peer_id: saorsa_gossip_types::PeerId,
}

impl std::fmt::Debug for KvStoreHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvStoreHandle")
            .field("agent_id", &self.agent_id)
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

impl KvStoreHandle {
    /// Return this handle's gossip peer id.
    #[must_use]
    pub fn peer_id(&self) -> saorsa_gossip_types::PeerId {
        self.peer_id
    }

    /// Put a key-value pair into the store.
    ///
    /// If the key already exists, the value is updated. Changes are
    /// automatically replicated to peers via gossip.
    ///
    /// # Errors
    ///
    /// Returns an error if the value exceeds the maximum inline size (64 KB).
    pub async fn put(
        &self,
        key: String,
        value: Vec<u8>,
        content_type: String,
    ) -> error::Result<()> {
        let _ = self.put_with_delta(key, value, content_type).await?;
        Ok(())
    }

    /// Put a key-value pair and return the CRDT delta that was published.
    ///
    /// This is used by API-layer delivery fallbacks that need to carry the
    /// exact same mutation over a side channel when pub/sub is congested.
    ///
    /// # Errors
    ///
    /// Returns an error if the value exceeds the maximum inline size (64 KB).
    pub async fn put_with_delta(
        &self,
        key: String,
        value: Vec<u8>,
        content_type: String,
    ) -> error::Result<kv::KvStoreDelta> {
        let delta = {
            let mut store = self.sync.write().await;
            store
                .put(
                    key.clone(),
                    value.clone(),
                    content_type.clone(),
                    self.peer_id,
                )
                .map_err(|e| {
                    error::IdentityError::Storage(std::io::Error::other(format!(
                        "kv put failed: {e}",
                    )))
                })?;
            let entry = store.get(&key).cloned();
            let version = store.current_version();
            match entry {
                Some(e) => {
                    kv::KvStoreDelta::for_put(key, e, (self.peer_id, store.next_seq()), version)
                }
                None => {
                    return Err(error::IdentityError::Storage(std::io::Error::other(
                        "kv put succeeded but entry was not readable",
                    )));
                }
            }
        };
        if let Err(e) = self.sync.publish_delta(self.peer_id, delta.clone()).await {
            tracing::warn!("failed to publish kv put delta: {e}");
        }
        Ok(delta)
    }

    /// Get a value by key.
    ///
    /// Returns `None` if the key does not exist or has been removed.
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be read.
    pub async fn get(&self, key: &str) -> error::Result<Option<KvEntrySnapshot>> {
        let store = self.sync.read().await;
        Ok(store.get(key).map(|e| KvEntrySnapshot {
            key: e.key.clone(),
            value: e.value.clone(),
            content_hash: hex::encode(e.content_hash),
            content_type: e.content_type.clone(),
            metadata: e.metadata.clone(),
            created_at: e.created_at,
            updated_at: e.updated_at,
        }))
    }

    /// Remove a key from the store.
    ///
    /// # Errors
    ///
    /// Returns an error if the key does not exist.
    pub async fn remove(&self, key: &str) -> error::Result<()> {
        let _ = self.remove_with_delta(key).await?;
        Ok(())
    }

    /// Remove a key and return the CRDT delta that was published.
    ///
    /// # Errors
    ///
    /// Returns an error if the key does not exist.
    pub async fn remove_with_delta(&self, key: &str) -> error::Result<kv::KvStoreDelta> {
        let delta = {
            let mut store = self.sync.write().await;
            store.remove(key).map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "kv remove failed: {e}",
                )))
            })?;
            let mut d = kv::KvStoreDelta::new(store.current_version());
            d.removed
                .insert(key.to_string(), std::collections::HashSet::new());
            d
        };
        if let Err(e) = self.sync.publish_delta(self.peer_id, delta.clone()).await {
            tracing::warn!("failed to publish kv remove delta: {e}");
        }
        Ok(delta)
    }

    /// Apply a verified remote delta received through a non-pubsub channel.
    ///
    /// # Errors
    ///
    /// Returns an error if the delta fails to merge into the local store.
    pub async fn apply_remote_delta(
        &self,
        peer_id: saorsa_gossip_types::PeerId,
        delta: &kv::KvStoreDelta,
        writer: Option<identity::AgentId>,
    ) -> error::Result<()> {
        let mut store = self.sync.write().await;
        store
            .merge_delta(delta, peer_id, writer.as_ref())
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "kv direct delta merge failed: {e}",
                )))
            })
    }

    /// List all active keys in the store.
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be read.
    pub async fn keys(&self) -> error::Result<Vec<KvEntrySnapshot>> {
        let store = self.sync.read().await;
        Ok(store
            .active_entries()
            .into_iter()
            .map(|e| KvEntrySnapshot {
                key: e.key.clone(),
                value: e.value.clone(),
                content_hash: hex::encode(e.content_hash),
                content_type: e.content_type.clone(),
                metadata: e.metadata.clone(),
                created_at: e.created_at,
                updated_at: e.updated_at,
            })
            .collect())
    }

    /// Get the store name.
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be read.
    pub async fn name(&self) -> error::Result<String> {
        let store = self.sync.read().await;
        Ok(store.name().to_string())
    }
}

/// Read-only snapshot of a KvStore entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KvEntrySnapshot {
    /// The key.
    pub key: String,
    /// The value bytes.
    pub value: Vec<u8>,
    /// BLAKE3 hash of the value (hex-encoded).
    pub content_hash: String,
    /// Content type (MIME).
    pub content_type: String,
    /// User metadata.
    pub metadata: std::collections::HashMap<String, String>,
    /// Unix milliseconds when created.
    pub created_at: u64,
    /// Unix milliseconds when last updated.
    pub updated_at: u64,
}

/// Read-only snapshot of a task's current state.
///
/// This is returned by `TaskListHandle::list_tasks()` and hides CRDT
/// internals, providing a clean API surface.
#[derive(Debug, Clone)]
pub struct TaskSnapshot {
    /// Unique task identifier.
    pub id: crdt::TaskId,
    /// Task title.
    pub title: String,
    /// Task description.
    pub description: String,
    /// Current checkbox state (Empty, Claimed, or Done).
    pub state: crdt::CheckboxState,
    /// Agent assigned to this task (if any).
    pub assignee: Option<identity::AgentId>,
    /// Human owner of the agent that created this task (if known).
    pub owner: Option<identity::UserId>,
    /// Task priority (0-255, higher = more important).
    pub priority: u8,
}

/// The x0x protocol version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The name. Three bytes. A palindrome. A philosophy.
pub const NAME: &str = "x0x";

/// X0X-0070b: drain inbound [`peer_relay::RelayedDm`] envelopes from
/// the [`network::NetworkNode`] and dispatch via the
/// [`peer_relay::PeerRelay`] engine. Spawned once per network-configured
/// [`Agent`] from [`AgentBuilder::build`].
///
/// # Per-arm behavior
///
/// * [`peer_relay::RelayDisposition::DeliverLocally`] - synthesises the
///   *original* sender's `MachineId`-as-`PeerId` from
///   `relayed.inner.sender_machine_id` and re-injects the inner
///   [`dm::DmEnvelope`] onto the canonical direct-DM channel via
///   [`network::NetworkNode::inject_inbound_direct`]. The downstream
///   direct-DM listener cannot distinguish a relayed packet from a
///   direct one.
/// * [`peer_relay::RelayDisposition::Forward`] - resolves `dst_agent_id`
///   to a `MachineId` via the identity-discovery cache, re-encodes the
///   inner envelope with postcard, and sends it on the standard
///   direct-DM stream ([`network::DIRECT_MESSAGE_STREAM_TYPE`]). The
///   wire prefix stamps *our* (the relay's) `AgentId` so the receiving
///   Agent's binding check at its direct listener (wire `sender_agent_id`
///   must match the QUIC peer's `MachineId`) passes - trust on the
///   inner envelope still flows from its embedded ML-DSA-65 signature.
///   If the destination is not in the discovery cache the forward
///   drops with a `warn!`.
/// * [`peer_relay::RelayDisposition::Refuse`] - `debug!` log only.
///   [`peer_relay::PeerRelay::disposition_for`] already incremented the
///   appropriate `relay_refused_*` counter as a side effect.
///
/// # Revocation gate
///
/// Before delivering locally or forwarding, the listener checks the
/// inner envelope's *origin* `sender_agent_id` against `revocation_set`.
/// This is required because the local-delivery path re-injects the inner
/// envelope onto the direct-DM channel
/// ([`network::NetworkNode::inject_inbound_direct`]), which does **not**
/// run the `dm_inbox` gossip-path revocation gate (#130). Without this
/// check a revoked agent that cannot direct-connect (e.g. NAT-blocked)
/// could still reach the recipient via a relay, bypassing revocation.
/// A revoked origin is dropped and counted as `relay_dropped_revoked`.
fn spawn_relay_dm_listener(
    network: std::sync::Arc<network::NetworkNode>,
    peer_relay: std::sync::Arc<peer_relay::PeerRelay>,
    identity_discovery_cache: std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<identity::AgentId, DiscoveredAgent>>,
    >,
    revocation_set: std::sync::Arc<tokio::sync::RwLock<revocation::RevocationSet>>,
    contact_store: std::sync::Arc<tokio::sync::RwLock<contacts::ContactStore>>,
    local_agent_id: identity::AgentId,
) {
    tokio::spawn(async move {
        tracing::info!(target: "x0x::relay", stage = "listener", "relay-DM listener started");
        loop {
            let Some((relay_peer_id, _relay_sender_agent_id, relayed)) =
                network.recv_relayed_dm().await
            else {
                tracing::warn!(
                    target: "x0x::relay",
                    stage = "listener",
                    "network.recv_relayed_dm channel closed - listener exiting"
                );
                break;
            };
            let now_ms = dm::now_unix_ms();
            // #193 contact gate: resolve the relay header's authenticated
            // sender against the contact store before classifying. The
            // gate itself is enforced inside `disposition_for`; this async
            // resolution belongs here (the contact store is an async
            // RwLock, and `disposition_for` is sync).
            //
            // Trust semantics: only *explicitly-trusted* contacts
            // (Known/Trusted) pass the gate — a merely-discovered
            // `Unknown` entry (auto-created by `register_announced_machine`
            // → `add_machine`, lib.rs ~576) does NOT, so the gate means
            // "my contacts", not "anyone I've seen". A `Blocked` entry is
            // refused unconditionally (see RelayRefusal::Blocked).
            //
            // TOCTOU: membership is snapshotted per message here and passed
            // as bools, so a contact removed/blocked mid-flight can have one
            // forward slip through before the next relay frame re-snapshots.
            // Acceptable — the inner DmEnvelope is end-to-end encrypted and
            // origin-signed, and the per-frame snapshot bounds the window to
            // a single hop.
            let sender_agent_id = identity::AgentId(relayed.header.sender_agent_id);
            let (is_sender_contact, is_sender_blocked) = {
                let store = contact_store.read().await;
                match store.get(&sender_agent_id) {
                    Some(c) => (
                        matches!(
                            c.trust_level,
                            contacts::TrustLevel::Known | contacts::TrustLevel::Trusted
                        ),
                        c.trust_level == contacts::TrustLevel::Blocked,
                    ),
                    None => (false, false),
                }
            };
            let disposition = peer_relay.disposition_for(
                &relayed,
                &local_agent_id,
                now_ms,
                is_sender_contact,
                is_sender_blocked,
            );

            // Revocation gate (PR #177 review, fix 1): the inner envelope's
            // ML-DSA-65 origin signature is the trust anchor, but a revoked
            // origin must be dropped even when it arrives via a relay. The
            // deliver/forward paths do not traverse the dm_inbox revocation
            // gate, so enforce it here for both, before any delivery.
            if matches!(
                disposition,
                peer_relay::RelayDisposition::DeliverLocally
                    | peer_relay::RelayDisposition::Forward { .. }
            ) {
                let origin = identity::AgentId(relayed.inner.sender_agent_id);
                let revoked = { revocation_set.read().await.is_agent_revoked(&origin) };
                if revoked {
                    peer_relay.record_relay_dropped_revoked();
                    tracing::info!(
                        target: "x0x::relay",
                        stage = "revoked_drop",
                        relay_peer = ?relay_peer_id,
                        origin = %hex::encode(origin.as_bytes()),
                        "relayed DM dropped: origin agent is revoked"
                    );
                    continue;
                }
            }

            match disposition {
                peer_relay::RelayDisposition::DeliverLocally => {
                    let sender_machine_id = relayed.inner.sender_machine_id;
                    let sender_peer_id = ant_quic::PeerId(sender_machine_id);
                    let inner_wire = match postcard::to_allocvec(&relayed.inner) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(
                                target: "x0x::relay",
                                stage = "deliver_local",
                                relay_peer = ?relay_peer_id,
                                error = %e,
                                "failed to re-encode inner envelope for local delivery"
                            );
                            continue;
                        }
                    };
                    // Wire shape mirrors the direct-DM listener's parse:
                    //   [sender_agent_id: 32][postcard(DmEnvelope)]
                    let mut payload = Vec::with_capacity(32 + inner_wire.len());
                    payload.extend_from_slice(&relayed.inner.sender_agent_id);
                    payload.extend_from_slice(&inner_wire);
                    if let Err(e) = network
                        .inject_inbound_direct(sender_peer_id, bytes::Bytes::from(payload))
                        .await
                    {
                        tracing::warn!(
                            target: "x0x::relay",
                            stage = "deliver_local",
                            relay_peer = ?relay_peer_id,
                            error = %e,
                            "DeliverLocally inject onto direct channel failed"
                        );
                    }
                }
                peer_relay::RelayDisposition::Forward { dst_agent_id } => {
                    let dst = identity::AgentId(dst_agent_id);
                    let dst_machine_id = {
                        let cache = identity_discovery_cache.read().await;
                        cache.get(&dst).map(|d| d.machine_id)
                    };
                    let Some(dst_machine_id) = dst_machine_id else {
                        tracing::warn!(
                            target: "x0x::relay",
                            stage = "forward",
                            dst = %hex::encode(dst.as_bytes()),
                            "Forward dropped: dst not in identity-discovery cache"
                        );
                        continue;
                    };
                    let inner_wire = match postcard::to_allocvec(&relayed.inner) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(
                                target: "x0x::relay",
                                stage = "forward",
                                dst = %hex::encode(dst.as_bytes()),
                                error = %e,
                                "failed to re-encode inner envelope for forward"
                            );
                            continue;
                        }
                    };
                    let dst_peer_id = ant_quic::PeerId(dst_machine_id.0);
                    if let Err(e) = network
                        .send_direct_typed(
                            &dst_peer_id,
                            local_agent_id.as_bytes(),
                            network::DIRECT_MESSAGE_STREAM_TYPE,
                            &inner_wire,
                        )
                        .await
                    {
                        tracing::warn!(
                            target: "x0x::relay",
                            stage = "forward",
                            dst = %hex::encode(dst.as_bytes()),
                            error = %e,
                            "Forward send_direct_typed failed"
                        );
                    }
                }
                peer_relay::RelayDisposition::Refuse(reason) => {
                    tracing::debug!(
                        target: "x0x::relay",
                        stage = "refuse",
                        relay_peer = ?relay_peer_id,
                        reason = ?reason,
                        "RelayedDm refused"
                    );
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> std::net::SocketAddr {
        s.parse().expect("valid SocketAddr literal in test")
    }

    #[test]
    fn discovery_rebroadcast_is_one_shot_per_announcement_key() {
        let now = std::time::Instant::now();
        let mut state = std::collections::HashMap::new();

        assert!(should_rebroadcast_discovery_once(
            &mut state,
            (7_u8, 42_u64),
            now
        ));
        assert!(!should_rebroadcast_discovery_once(
            &mut state,
            (7_u8, 42_u64),
            now + std::time::Duration::from_secs(20),
        ));
        assert!(should_rebroadcast_discovery_once(
            &mut state,
            (7_u8, 43_u64),
            now + std::time::Duration::from_secs(20),
        ));
    }

    #[test]
    fn discovery_ttl_uses_local_last_seen_not_sender_timestamp() {
        let cutoff = 900;

        assert!(discovery_record_is_live(100, 1_000, cutoff));
        assert!(discovery_record_is_live(10_000, cutoff, cutoff));
        assert!(!discovery_record_is_live(10_000, cutoff - 1, cutoff));
    }

    #[test]
    fn is_publicly_advertisable_rejects_lan_and_special_scopes() {
        // v4 non-global scopes
        assert!(
            !is_publicly_advertisable(sa("127.0.0.1:5483")),
            "loopback v4"
        );
        assert!(!is_publicly_advertisable(sa("10.1.2.3:5483")), "rfc1918 /8");
        assert!(
            !is_publicly_advertisable(sa("172.20.0.5:5483")),
            "rfc1918 /12"
        );
        assert!(
            !is_publicly_advertisable(sa("192.168.1.5:5483")),
            "rfc1918 /16"
        );
        assert!(
            !is_publicly_advertisable(sa("169.254.1.1:5483")),
            "link-local v4"
        );
        assert!(
            !is_publicly_advertisable(sa("100.64.1.1:5483")),
            "CGNAT (unreachable outside carrier)"
        );
        assert!(
            !is_publicly_advertisable(sa("0.0.0.0:5483")),
            "unspecified v4"
        );

        // v6 non-global scopes
        assert!(!is_publicly_advertisable(sa("[::1]:5483")), "loopback v6");
        assert!(
            !is_publicly_advertisable(sa("[fe80::1]:5483")),
            "link-local v6"
        );
        assert!(!is_publicly_advertisable(sa("[fd00::1]:5483")), "ULA v6");

        // port 0 never advertisable regardless of ip scope
        assert!(
            !is_publicly_advertisable(sa("1.2.3.4:0")),
            "port 0 on global v4"
        );

        // Globally-routable positives
        assert!(is_publicly_advertisable(sa("1.2.3.4:5483")), "global v4");
        assert!(
            is_publicly_advertisable(sa("[2001:db8::1]:5483")),
            "global v6 (documentation doc but is_globally_routable permits)",
        );
        assert!(
            is_publicly_advertisable(sa("8.8.8.8:9000")),
            "global v4 on non-default port",
        );

        // Reserved documentation ranges are correctly rejected by
        // is_globally_routable even though they are not RFC1918.
        assert!(
            !is_publicly_advertisable(sa("192.0.2.1:5483")),
            "TEST-NET-1 documentation range"
        );
        assert!(
            !is_publicly_advertisable(sa("203.0.113.10:5483")),
            "TEST-NET-3 documentation range"
        );
    }

    #[test]
    fn public_address_filter_drops_global_discovery_unsafe_candidates() {
        let filtered = filter_publicly_advertisable_addrs(vec![
            sa("127.0.0.1:5483"),
            sa("10.1.2.3:5483"),
            sa("100.64.1.1:5483"),
            sa("169.254.1.1:5483"),
            sa("1.2.3.4:0"),
            sa("[::1]:5483"),
            sa("[fd00::1]:5483"),
            sa("8.8.8.8:5483"),
            sa("[2001:db8::1]:5483"),
        ]);

        assert_eq!(filtered, vec![sa("8.8.8.8:5483"), sa("[2001:db8::1]:5483")]);
    }

    #[test]
    fn local_discovery_filter_keeps_same_partition_candidates() {
        let filtered = filter_discovery_announcement_addrs(
            vec![
                sa("127.0.0.1:5483"),
                sa("10.1.2.3:5483"),
                sa("100.64.1.1:5483"),
                sa("169.254.1.1:5483"),
                sa("1.2.3.4:0"),
                sa("[::1]:5483"),
                sa("[fd00::1]:5483"),
                sa("8.8.8.8:5483"),
            ],
            true,
        );

        assert_eq!(
            filtered,
            vec![
                sa("127.0.0.1:5483"),
                sa("10.1.2.3:5483"),
                sa("100.64.1.1:5483"),
                sa("[::1]:5483"),
                sa("[fd00::1]:5483"),
                sa("8.8.8.8:5483"),
            ],
        );
    }

    #[test]
    fn local_discovery_scope_tracks_bootstrap_partition() {
        let mut config = network::NetworkConfig {
            bootstrap_nodes: Vec::new(),
            ..network::NetworkConfig::default()
        };
        assert!(allow_local_discovery_addresses(&config));

        config.bootstrap_nodes = vec![sa("127.0.0.1:5483"), sa("192.168.1.10:5483")];
        assert!(allow_local_discovery_addresses(&config));

        config.bootstrap_nodes = vec![sa("127.0.0.1:5483"), sa("8.8.8.8:5483")];
        assert!(!allow_local_discovery_addresses(&config));
    }

    #[test]
    fn local_direct_probe_addrs_prioritizes_same_lan_ipv4() {
        let local = [std::net::Ipv4Addr::new(192, 168, 1, 212)];
        let ranked = local_direct_probe_addrs_with_local_v4s(
            &[
                sa("100.118.167.101:27749"),
                sa("192.168.0.1:27749"),
                sa("192.168.1.108:27749"),
                sa("[2a0d:3344:32d:2e10::1]:27749"),
                sa("[fd7a:115c:a1e0::b01:a7ac]:27749"),
            ],
            &local,
        );

        assert_eq!(
            ranked,
            vec![
                sa("192.168.1.108:27749"),
                sa("192.168.0.1:27749"),
                sa("100.118.167.101:27749"),
            ],
        );
    }

    #[tokio::test]
    async fn announcement_builders_filter_global_discovery_addresses() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .build()
            .await
            .expect("agent");
        let addresses = vec![
            sa("192.168.1.5:5483"),
            sa("100.64.1.1:5483"),
            sa("1.2.3.4:0"),
            sa("8.8.8.8:5483"),
            sa("[fd00::1]:5483"),
            sa("[2001:db8::1]:5483"),
        ];
        let expected = vec![sa("8.8.8.8:5483"), sa("[2001:db8::1]:5483")];

        let identity_announcement = agent
            .build_identity_announcement_with_addrs(IdentityAnnouncementBuildOptions {
                include_user_identity: false,
                human_consent: false,
                addresses: addresses.clone(),
                assist_snapshot: None,
                reachable_via: Vec::new(),
                relay_candidates: Vec::new(),
                allow_local_scope: false,
            })
            .expect("identity announcement");
        assert_eq!(identity_announcement.addresses, expected);
        identity_announcement
            .verify()
            .expect("filtered identity announcement verifies");

        let machine_announcement = build_machine_announcement_for_identity(
            &agent.identity,
            addresses,
            1,
            None,
            Vec::new(),
            Vec::new(),
            false,
        )
        .expect("machine announcement");
        assert_eq!(machine_announcement.addresses, expected);
        machine_announcement
            .verify()
            .expect("filtered machine announcement verifies");
    }

    #[test]
    fn presence_parse_addr_hints_drops_private_scopes() {
        // Older peers ship a mix of scopes. parse_addr_hints should return only
        // globally-advertisable entries so our dial loop never burns budget on
        // unreachable candidates.
        let hints = vec![
            "127.0.0.1:5483".to_string(),
            "10.200.0.1:5483".to_string(),
            "[fd00::1]:5483".to_string(),
            "1.2.3.4:5483".to_string(),
            "[2001:db8::1]:5483".to_string(),
            "not-an-address".to_string(),
        ];
        let parsed = presence::parse_addr_hints(&hints);
        let got: Vec<String> = parsed.iter().map(|a| a.to_string()).collect();
        assert_eq!(
            got,
            vec!["1.2.3.4:5483".to_string(), "[2001:db8::1]:5483".to_string()],
            "only globally-advertisable addresses survive inbound parsing"
        );
    }

    #[test]
    fn name_is_palindrome() {
        let name = NAME;
        let reversed: String = name.chars().rev().collect();
        assert_eq!(name, reversed, "x0x must be a palindrome");
    }

    #[test]
    fn name_is_three_bytes() {
        assert_eq!(NAME.len(), 3, "x0x must be exactly three bytes");
    }

    #[test]
    fn name_is_ai_native() {
        // No uppercase, no spaces, no special chars that conflict
        // with shell, YAML, Markdown, or URL encoding
        assert!(NAME.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn raw_quic_receive_ack_failure_falls_back_when_gossip_available() {
        let err = error::NetworkError::ConnectionFailed(
            "send_with_receive_ack failed: Connection closed: Superseded".to_string(),
        );
        assert!(
            !Agent::raw_quic_error_should_stop_fallback(&err, true),
            "transient raw ACK lifecycle churn should not suppress gossip fallback"
        );
        assert!(
            Agent::raw_quic_error_should_stop_fallback(&err, false),
            "without a gossip capability, the raw ACK failure remains terminal"
        );
    }

    #[test]
    fn raw_quic_receive_backpressure_falls_back_when_gossip_available() {
        let err = error::NetworkError::RemoteReceiveBackpressured(
            "send_with_receive_ack failed: Remote receive pipeline rejected payload: Backpressured"
                .to_string(),
        );
        assert!(
            !Agent::raw_quic_error_should_stop_fallback(&err, true),
            "receiver congestion should allow gossip fallback"
        );
        assert!(
            Agent::raw_quic_error_should_stop_fallback(&err, false),
            "without a gossip capability, receiver congestion remains terminal"
        );
        assert!(matches!(
            Agent::map_raw_quic_dm_error(err),
            dm::DmError::ReceiverBackpressured { .. }
        ));
    }

    #[test]
    fn raw_quic_payload_errors_still_stop_fallback() {
        let err = error::NetworkError::PayloadTooLarge { size: 2, max: 1 };
        assert!(Agent::raw_quic_error_should_stop_fallback(&err, true));
    }

    #[tokio::test]
    async fn unusable_capability_advert_falls_back_to_contact_card() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .build()
            .await
            .expect("agent");
        let target = identity::AgentId([7_u8; 32]);
        let target_machine = identity::MachineId([9_u8; 32]);

        agent.capability_store().insert(
            target,
            target_machine,
            dm::DmCapabilities::pending(),
            dm_capability::now_unix_ms(),
        );
        agent.contacts().write().await.add(contacts::Contact {
            agent_id: target,
            trust_level: contacts::TrustLevel::Trusted,
            label: None,
            added_at: 0,
            last_seen: None,
            identity_type: contacts::IdentityType::Known,
            machines: Vec::new(),
            dm_capabilities: Some(dm::DmCapabilities::v1_gossip_ready(vec![42_u8; 1184])),
        });

        let err = agent
            .send_direct_with_config(
                &target,
                b"contact-card-capability".to_vec(),
                dm::DmSendConfig {
                    require_gossip: true,
                    ..dm::DmSendConfig::default()
                },
            )
            .await
            .expect_err("contact-card capability should be used before gossip runtime fails");

        assert!(
            matches!(err, dm::DmError::LocalGossipUnavailable(_)),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn self_dm_uses_loopback_and_delivers_to_subscribers() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .build()
            .await
            .expect("agent");
        let mut rx = agent.subscribe_direct();
        let payload = b"loopback-self-dm".to_vec();

        let receipt = agent
            .send_direct_with_config(
                &agent.agent_id(),
                payload.clone(),
                dm::DmSendConfig::default(),
            )
            .await
            .expect("self-DM should use loopback path");

        assert_eq!(receipt.path, dm::DmPath::Loopback);
        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("self-DM should be delivered promptly")
            .expect("subscriber should remain open");
        assert_eq!(msg.sender, agent.agent_id());
        assert_eq!(msg.machine_id, agent.machine_id());
        assert_eq!(msg.payload, payload);
        assert!(msg.verified);
        assert_eq!(msg.trust_decision, Some(trust::TrustDecision::Accept));

        let diagnostics = agent.direct_messaging().diagnostics_snapshot();
        assert_eq!(diagnostics.stats.outgoing_send_succeeded, 1);
        assert_eq!(diagnostics.stats.outgoing_path_loopback, 1);
        assert_eq!(diagnostics.stats.incoming_envelopes_total, 1);
        assert_eq!(diagnostics.stats.incoming_delivered_to_subscribe, 1);
    }

    fn loopback_network_config() -> network::NetworkConfig {
        network::NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr")),
            bootstrap_nodes: Vec::new(),
            ..network::NetworkConfig::default()
        }
    }

    fn normalize_loopback_addr(addr: std::net::SocketAddr) -> std::net::SocketAddr {
        if addr.ip().is_unspecified() {
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                addr.port(),
            )
        } else {
            addr
        }
    }

    #[tokio::test]
    async fn shutdown_aborts_identity_heartbeat_task() {
        struct DropFlag(std::sync::Arc<std::sync::atomic::AtomicBool>);

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::Release);
            }
        }

        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .build()
            .await
            .expect("agent");

        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped_for_task = std::sync::Arc::clone(&dropped);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let _drop_flag = DropFlag(dropped_for_task);
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.expect("heartbeat task started");

        *agent.heartbeat_handle.lock().await = Some(handle);
        assert!(agent.heartbeat_handle.lock().await.is_some());

        agent.shutdown().await;
        assert!(agent.heartbeat_handle.lock().await.is_none());
        assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
    }

    /// Issue #126 / WS1.5: the delta-merge + state-request subscription loops
    /// spawned by `create_kv_store` / `create_task_list` must be routed through
    /// `spawn_tracked` so `Agent::shutdown()` drains and aborts them. Previously
    /// they detached via bare `tokio::spawn` and only ended when the gossip
    /// runtime later dropped its topic sender.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shutdown_drains_crdt_kv_sync_tasks() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .with_peer_cache_disabled()
            .with_network_config(loopback_network_config())
            .build()
            .await
            .expect("agent");

        // Build() constructs the gossip runtime, so creating a store + a list
        // works without join_network. Each creation spawns the delta-merge and
        // state-request subscription loops (plus a bounded bootstrap requester
        // for an empty store/list).
        let baseline = agent
            .tracked_tasks
            .lock()
            .expect("tracked_tasks")
            .handles
            .len();

        agent
            .create_kv_store("ws15-store", "ws15-store-topic")
            .await
            .expect("create kv store");
        agent
            .create_task_list("ws15-list", "ws15-list-topic")
            .await
            .expect("create task list");

        // The loops must now be registered with spawn_tracked. With the old bare
        // tokio::spawn this count would NOT have moved.
        let (registered, abort_handles): (usize, Vec<tokio::task::AbortHandle>) = {
            let guard = agent.tracked_tasks.lock().expect("tracked_tasks");
            let aborts = guard.handles.iter().map(|h| h.abort_handle()).collect();
            (guard.handles.len(), aborts)
        };
        assert!(
            registered > baseline,
            "CRDT/KV sync loops must register with spawn_tracked \
             (registry {registered}, baseline {baseline})"
        );

        agent.shutdown().await;

        // shutdown() closes the registry and drains it (handles taken, grace-
        // awaited, stragglers aborted).
        let after = agent.tracked_tasks.lock().expect("tracked_tasks");
        assert!(
            after.closed,
            "tracked-task registry must be closed after shutdown"
        );
        assert!(
            after.handles.is_empty(),
            "tracked-task registry must be drained after shutdown ({} left)",
            after.handles.len()
        );
        drop(after);

        // Every formerly-tracked sync loop terminated.
        for handle in &abort_handles {
            assert!(
                handle.is_finished(),
                "a CRDT/KV sync task did not terminate after shutdown"
            );
        }
    }

    // ========================================================================
    // #124 / WS1.3 tranche 4 — shutdown ordering invariants.
    //
    // `shutdown()` and `begin_shutdown()` carry ordering guarantees that are
    // themselves correctness properties (a still-running join_network must not
    // leak a task past shutdown; a second shutdown must never panic; a token-
    // respecting task must be graced, not force-aborted). These pin them as
    // fast, daemon-free unit tests. The WS/SSE close-on-shutdown notification
    // path is already covered at integration tier by
    // `daemon_api_shutdown_with_sse_client` and is not re-duplicated here
    // (avoiding a src/server/mod.rs touch during Eng B's #125 window).
    // ========================================================================

    /// `begin_shutdown()` is the synchronous shutdown prefix: it cancels the
    /// token AND closes the tracked-task registry, without draining. After it
    /// returns, `spawn_tracked` must refuse (next test) and a subsequent
    /// `shutdown()` must still complete cleanly. Pins that the two halves of
    /// the shutdown signal — token + closed-flag — move together.
    #[tokio::test]
    async fn begin_shutdown_closes_registry_and_cancels_token() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .build()
            .await
            .expect("agent");

        assert!(
            !agent.shutdown_token.is_cancelled(),
            "token must not be cancelled before shutdown begins"
        );
        assert!(
            !agent.tracked_tasks.lock().expect("tracked_tasks").closed,
            "registry must be open before shutdown begins"
        );

        agent.begin_shutdown();

        assert!(
            agent.shutdown_token.is_cancelled(),
            "begin_shutdown must cancel the shutdown token"
        );
        assert!(
            agent.tracked_tasks.lock().expect("tracked_tasks").closed,
            "begin_shutdown must close the tracked-task registry"
        );

        // begin_shutdown does NOT drain — that is shutdown()'s job. The handles
        // must still be present (untouched) until shutdown() runs.
        // (None were spawned here, so the registry is empty-but-closed.)
    }

    /// Once `begin_shutdown()` has closed the registry, `spawn_tracked` must be
    /// a no-op: the handle is NOT pushed. This is the invariant that defeats a
    /// racing `join_network` from leaking heartbeat/reaper/presence tasks past
    /// the subsequent `shutdown()` (the registry drains empty because nothing
    // new can enter after close).
    #[tokio::test]
    async fn spawn_tracked_refuses_after_begin_shutdown() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .build()
            .await
            .expect("agent");

        // Before begin_shutdown: spawn_tracked accepts.
        agent.spawn_tracked(async {});
        let before = agent
            .tracked_tasks
            .lock()
            .expect("tracked_tasks")
            .handles
            .len();
        assert_eq!(
            before, 1,
            "spawn_tracked must register a task before begin_shutdown"
        );

        // Close the registry, then attempt another spawn.
        agent.begin_shutdown();
        agent.spawn_tracked(async {});

        {
            let after = agent.tracked_tasks.lock().expect("tracked_tasks");
            assert_eq!(
                after.handles.len(),
                before,
                "spawn_tracked must be a no-op (handle NOT pushed) after begin_shutdown \
                 closed the registry — a racing join_network would otherwise leak a task"
            );
            assert!(after.closed, "registry must remain closed");
        }

        // Clean up the one task we did register so it does not outlive the test.
        agent.shutdown().await;
    }

    /// `shutdown()` is documented idempotent: `cancel()` is idempotent, the
    /// registry drains empty on a second call, and the `Option<JoinHandle>`
    /// `stop_*` helpers use `Option::take` (a second take is None). Pin that a
    /// double shutdown never panics and leaves the registry drained.
    #[tokio::test]
    async fn shutdown_is_idempotent_and_never_panics_on_second_call() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .build()
            .await
            .expect("agent");

        agent.shutdown().await;
        // The invariant: a second shutdown must be a safe no-op, never panic
        // (an embedder re-entering shutdown on an error path must not crash).
        agent.shutdown().await;

        let registry = agent.tracked_tasks.lock().expect("tracked_tasks");
        assert!(
            registry.closed,
            "registry must remain closed after a double shutdown"
        );
        assert!(
            registry.handles.is_empty(),
            "registry must be drained after a double shutdown"
        );
        assert!(
            agent.shutdown_token.is_cancelled(),
            "token must remain cancelled after a double shutdown"
        );
    }

    /// Shutdown ordering: the registry grace-awaits tracked tasks BEFORE any
    /// straggler is force-aborted. So a task that RESPECTS the token (awaits
    /// `shutdown_token.cancelled()`) must run to its natural end and set its
    /// completed-flag — it is graced, not aborted. This is the positive arm of
    /// the grace/abort policy.
    ///
    /// NOTE: we deliberately do NOT assert what the task observes for
    /// `is_cancelled()` at first-poll. On a multi-thread runtime `tokio::spawn`
    /// may schedule the task onto another worker that polls it BEFORE
    /// `shutdown()` runs on this thread, so first-poll-observes-cancelled is a
    /// race, not an invariant. The robust, non-racy claim is grace-before-abort:
    /// the well-behaved task completes naturally (sets its flag) rather than
    /// being force-aborted by the 3s-straggler path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shutdown_graces_a_token_respecting_tracked_task() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .build()
            .await
            .expect("agent");

        // A token-respecting task: it records that it reached its natural end
        // (graceful completion, never aborted). If the grace-await path broke
        // (e.g. the task were force-aborted), this flag would stay false.
        let completed_gracefully = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let token = agent.shutdown_token.clone();
        let cg = std::sync::Arc::clone(&completed_gracefully);
        agent.spawn_tracked(async move {
            // Graceful: stop as soon as the token fires, without being aborted.
            token.cancelled().await;
            cg.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        agent.shutdown().await;

        assert!(
            completed_gracefully.load(std::sync::atomic::Ordering::SeqCst),
            "token-respecting task must complete GRACEFULLY (set its flag before \
             returning) — proves the grace-await precedes any force-abort"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn connected_peer_clears_stale_lifecycle_block_before_raw_send() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let alice = Agent::builder()
            .with_machine_key(dir.path().join("alice-machine.key"))
            .with_agent_key_path(dir.path().join("alice-agent.key"))
            .with_contact_store_path(dir.path().join("alice-contacts.json"))
            .with_peer_cache_disabled()
            .with_network_config(loopback_network_config())
            .build()
            .await
            .expect("alice");
        let bob = Agent::builder()
            .with_machine_key(dir.path().join("bob-machine.key"))
            .with_agent_key_path(dir.path().join("bob-agent.key"))
            .with_contact_store_path(dir.path().join("bob-contacts.json"))
            .with_peer_cache_disabled()
            .with_network_config(loopback_network_config())
            .build()
            .await
            .expect("bob");

        let bob_network = bob.network().expect("bob network");
        let bob_addr = normalize_loopback_addr(bob_network.bound_addr().await.expect("bob bound"));
        let alice_network = alice.network().expect("alice network");
        let connected_peer = alice_network
            .connect_addr(bob_addr)
            .await
            .expect("alice connects to bob");
        assert_eq!(connected_peer.0, bob.machine_id().0);

        let bob_peer = ant_quic::PeerId(bob.machine_id().0);
        let connected_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while tokio::time::Instant::now() < connected_deadline {
            if alice_network.is_connected(&bob_peer).await {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(alice_network.is_connected(&bob_peer).await);

        alice
            .direct_messaging()
            .mark_connected(bob.agent_id(), bob.machine_id())
            .await;
        alice.direct_messaging().record_lifecycle_blocked(
            bob.machine_id(),
            Some(1),
            "closed: stale test block",
        );
        assert!(alice
            .direct_messaging()
            .lifecycle_block_reason(&bob.machine_id())
            .is_some());

        let receipt = alice
            .send_direct_with_config(
                &bob.agent_id(),
                b"stale-block-clear".to_vec(),
                dm::DmSendConfig {
                    prefer_raw_quic_if_connected: true,
                    ..dm::DmSendConfig::default()
                },
            )
            .await
            .expect("raw send should ignore and clear stale lifecycle block");
        assert_eq!(receipt.path, dm::DmPath::RawQuic);
        assert!(alice
            .direct_messaging()
            .lifecycle_block_reason(&bob.machine_id())
            .is_none());
    }

    #[tokio::test]
    async fn agent_peer_relay_defaults_to_disabled_when_unconfigured() {
        // Why: X0X-0070b's relay engine is opt-in. An Agent built without
        // any `[peer_relay]` TOML section must come up with the engine
        // disabled and an empty candidate list - anything else would
        // engage the fallback for operators who never asked for it.
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .build()
            .await
            .expect("agent");
        assert!(
            !agent.peer_relay().policy().enabled,
            "default Agent must have the relay engine disabled"
        );
        assert!(
            agent.relay_candidates().await.is_empty(),
            "default Agent must have no relay candidates"
        );
    }

    #[tokio::test]
    async fn agent_peer_relay_honors_configured_policy_and_candidates() {
        // Why: a TOML-configured `[peer_relay]` block must flow through to
        // a live `PeerRelay` instance on the Agent - enabled flag, fail
        // trigger, and the seeded candidate list. This is the single
        // integration seam where an operator's config first takes effect.
        let dir = tempfile::tempdir().expect("tmpdir");
        let candidate_a = [0xAA_u8; 32];
        let candidate_b = [0xBB_u8; 32];
        let mut net_cfg = loopback_network_config();
        net_cfg.peer_relay = network::PeerRelayConfig {
            enabled: true,
            require_contact_to_relay: false,
            fail_threshold: 7,
            fail_window_ms: 90_000,
            candidates: vec![hex::encode(candidate_a), hex::encode(candidate_b)],
            ..Default::default()
        };
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .with_peer_cache_disabled()
            .with_network_config(net_cfg)
            .build()
            .await
            .expect("agent");

        let policy = agent.peer_relay().policy();
        assert!(policy.enabled, "configured `enabled = true` must propagate");
        assert_eq!(policy.fail_threshold, 7);
        assert_eq!(policy.fail_window, std::time::Duration::from_millis(90_000));

        let candidates = agent.relay_candidates().await;
        assert_eq!(candidates.len(), 2, "both TOML candidates seeded");
        assert!(candidates.iter().any(|c| c.0 == candidate_a));
        assert!(candidates.iter().any(|c| c.0 == candidate_b));
    }

    #[tokio::test]
    async fn send_direct_failure_records_failure_on_peer_relay() {
        // Why: the bookkeeping hook in `send_direct_with_config` is the
        // single feed into `PeerRelay::needs_relay`. If a transport
        // failure does not increment the per-peer failure count, the
        // engine can never decide to engage the relay - the fallback is
        // dead-on-arrival. With no network configured every raw-QUIC
        // attempt fails fast, which gives a deterministic test signal.
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .build()
            .await
            .expect("agent");
        let unreachable = identity::AgentId([0x42; 32]);

        let result = agent
            .send_direct_with_config(
                &unreachable,
                b"x0x-0070b-bookkeeping".to_vec(),
                dm::DmSendConfig::default(),
            )
            .await;
        assert!(
            result.is_err(),
            "no network configured - direct send must fail"
        );
        assert_eq!(
            agent.peer_relay().tracked_peer_count(),
            1,
            "failure must have produced a per-peer relay-engine entry"
        );
    }

    #[tokio::test]
    async fn send_direct_self_loopback_does_not_disturb_peer_relay() {
        // Why: the loopback short-circuit at the top of
        // `send_direct_with_config` returns before the bookkeeping arm.
        // A self-DM must not count as a "direct success" against the
        // sender's own AgentId - that would conflate local delivery
        // with the cross-peer path that actually exercises NAT.
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .build()
            .await
            .expect("agent");
        let _receipt = agent
            .send_direct_with_config(
                &agent.agent_id(),
                b"loopback".to_vec(),
                dm::DmSendConfig::default(),
            )
            .await
            .expect("loopback self-DM");
        assert_eq!(
            agent.peer_relay().tracked_peer_count(),
            0,
            "loopback path must not register with the relay engine"
        );
    }

    #[tokio::test]
    async fn try_relay_fallback_returns_no_candidate_when_list_empty() {
        // Why: with an enabled policy but zero seeded candidates,
        // `select_relay` returns `None` and the helper must short-circuit
        // to `NoRelayCandidate`. Falling through to envelope construction
        // would burn KEM/AEAD cycles for nothing.
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut net_cfg = loopback_network_config();
        net_cfg.peer_relay = network::PeerRelayConfig {
            enabled: true,
            require_contact_to_relay: false,
            fail_threshold: 3,
            fail_window_ms: 60_000,
            candidates: Vec::new(),
            ..Default::default()
        };
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .with_peer_cache_disabled()
            .with_network_config(net_cfg)
            .build()
            .await
            .expect("agent");
        let to = identity::AgentId([0xCD; 32]);

        let err = agent
            .try_relay_fallback(&to, b"payload".to_vec(), &[0u8; 32])
            .await
            .expect_err("empty candidate list must short-circuit");
        assert!(
            matches!(err, dm::DmError::NoRelayCandidate),
            "expected NoRelayCandidate, got {err:?}"
        );
    }

    #[tokio::test]
    async fn try_relay_fallback_returns_no_candidate_when_machine_id_uncached() {
        // Why: a seeded candidate AgentId is useless if its MachineId is
        // not in the identity-discovery cache - we need it to address
        // the QUIC peer at the wire layer. The helper must treat this
        // as "no usable candidate" and let the caller surface the
        // original direct error.
        let dir = tempfile::tempdir().expect("tmpdir");
        let candidate_hex = hex::encode([0xEE_u8; 32]);
        let mut net_cfg = loopback_network_config();
        net_cfg.peer_relay = network::PeerRelayConfig {
            enabled: true,
            require_contact_to_relay: false,
            fail_threshold: 3,
            fail_window_ms: 60_000,
            candidates: vec![candidate_hex],
            ..Default::default()
        };
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .with_peer_cache_disabled()
            .with_network_config(net_cfg)
            .build()
            .await
            .expect("agent");
        let to = identity::AgentId([0xCD; 32]);

        let err = agent
            .try_relay_fallback(&to, b"payload".to_vec(), &[0u8; 32])
            .await
            .expect_err("uncached candidate must short-circuit");
        assert!(
            matches!(err, dm::DmError::NoRelayCandidate),
            "expected NoRelayCandidate, got {err:?}"
        );
    }

    #[tokio::test]
    async fn send_direct_below_threshold_does_not_attempt_relay() {
        // Why: the engine must wait until the sliding-window failure
        // count reaches `fail_threshold` before engaging the relay.
        // A single transport failure must surface the original direct
        // error AND must not register `relay_sent` on the engine
        // (proves no fallback attempt fired underneath).
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut net_cfg = loopback_network_config();
        net_cfg.peer_relay = network::PeerRelayConfig {
            enabled: true,
            require_contact_to_relay: false,
            fail_threshold: 5,
            fail_window_ms: 60_000,
            candidates: vec![hex::encode([0xEE_u8; 32])],
            ..Default::default()
        };
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .with_peer_cache_disabled()
            .with_network_config(net_cfg)
            .build()
            .await
            .expect("agent");
        let to = identity::AgentId([0xCD; 32]);

        let result = agent
            .send_direct_with_config(&to, b"first-attempt".to_vec(), dm::DmSendConfig::default())
            .await;
        assert!(result.is_err(), "no usable transport - direct send fails");
        let snap = agent.peer_relay().stats().snapshot();
        assert_eq!(
            snap.relay_sent, 0,
            "below threshold must not engage the relay path"
        );
    }

    #[tokio::test]
    async fn send_direct_above_threshold_without_candidates_surfaces_direct_err() {
        // Why: the contract for relay-fallback failure is that the
        // caller sees the ORIGINAL direct error, never the relay-side
        // bookkeeping error. Pre-load the engine past threshold, then
        // send to a peer with no usable candidate - the result must
        // be a direct-transport error, not `NoRelayCandidate`.
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut net_cfg = loopback_network_config();
        net_cfg.peer_relay = network::PeerRelayConfig {
            enabled: true,
            require_contact_to_relay: false,
            fail_threshold: 3,
            fail_window_ms: 60_000,
            candidates: Vec::new(),
            ..Default::default()
        };
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .with_peer_cache_disabled()
            .with_network_config(net_cfg)
            .build()
            .await
            .expect("agent");
        let to = identity::AgentId([0xCD; 32]);

        // Pre-load the engine past threshold without waiting for live
        // transport retries.
        for _ in 0..agent.peer_relay().policy().fail_threshold {
            agent.peer_relay().record_direct_failure(&to);
        }
        assert!(
            agent.peer_relay().needs_relay(&to),
            "engine must say the peer now needs a relay"
        );

        let err = agent
            .send_direct_with_config(&to, b"x0x-0070b".to_vec(), dm::DmSendConfig::default())
            .await
            .expect_err("send must still fail when the relay path has no candidates");
        assert!(
            !matches!(err, dm::DmError::NoRelayCandidate),
            "relay-side errors must not leak - original direct error must surface, got {err:?}"
        );
    }

    #[tokio::test]
    async fn send_direct_disabled_policy_does_not_engage_relay_seed() {
        // Why: with the default disabled policy the relay-seed clone
        // must not happen - the happy path pays nothing. Even with the
        // peer manually driven past `fail_threshold` (which would never
        // happen under a disabled policy in practice, but is a
        // belt-and-braces check), the engine's `needs_relay` stays
        // `false` and no fallback fires.
        let dir = tempfile::tempdir().expect("tmpdir");
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .build()
            .await
            .expect("agent");
        let to = identity::AgentId([0xCD; 32]);
        for _ in 0..10 {
            agent.peer_relay().record_direct_failure(&to);
        }
        assert!(
            !agent.peer_relay().needs_relay(&to),
            "disabled policy must never trigger needs_relay"
        );

        let err = agent
            .send_direct_with_config(&to, b"x0x-0070b".to_vec(), dm::DmSendConfig::default())
            .await
            .expect_err("no network - direct send must fail");
        assert!(
            !matches!(err, dm::DmError::NoRelayCandidate),
            "disabled policy must not surface any relay-side error, got {err:?}"
        );
        assert_eq!(
            agent.peer_relay().stats().snapshot().relay_sent,
            0,
            "disabled policy must not advance relay_sent"
        );
    }

    #[tokio::test]
    async fn relay_dm_listener_refuses_bad_signature_and_ticks_counter() {
        // Why: the receiver-side surface for X0X-0070b - a single
        // demux arm + a listener loop that runs `disposition_for` and
        // dispatches the three arms - depends on the listener actually
        // draining `network.recv_relayed_dm`. If the spawn ever drops
        // (forgotten in `AgentBuilder::build`, or the wire/channel
        // shape drifts) the engine silently stops refusing replays
        // and forwards, and the bug presents as "relay path is
        // configured but nothing happens." Pin the end-to-end
        // channel + loop liveness with the cheapest fully-typed
        // signal we have: a `RelayedDm` with an obviously-broken
        // header signature flows through the channel, the listener
        // consumes it, `disposition_for` returns
        // `Refuse(BadSignature)`, and the
        // `relay_refused_bad_signature` counter ticks. Catches any
        // future channel-rename / spawn-drop / wire-type regression.
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut net_cfg = loopback_network_config();
        net_cfg.peer_relay = network::PeerRelayConfig {
            enabled: true,
            require_contact_to_relay: false,
            fail_threshold: 3,
            fail_window_ms: 60_000,
            candidates: Vec::new(),
            ..Default::default()
        };
        let agent = Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .with_peer_cache_disabled()
            .with_network_config(net_cfg)
            .build()
            .await
            .expect("agent");

        let network = agent
            .network
            .as_ref()
            .expect("agent built with network config");
        let sender = network.test_relayed_dm_sender();

        let relayed = peer_relay::RelayedDm {
            header: peer_relay::RelayHeader {
                version: peer_relay::RelayHeader::VERSION,
                dst_agent_id: agent.agent_id().0,
                sender_agent_id: [0x42; 32],
                // Empty pubkey + signature: header.verify() must fail.
                sender_public_key: Vec::new(),
                originated_at_unix_ms: dm::now_unix_ms(),
                signature: Vec::new(),
            },
            inner: dm::DmEnvelope {
                protocol_version: 1,
                request_id: [0u8; 16],
                sender_agent_id: [0x42; 32],
                sender_machine_id: [0x43; 32],
                recipient_agent_id: agent.agent_id().0,
                created_at_unix_ms: 0,
                expires_at_unix_ms: 0,
                body: dm::DmBody::Payload(dm::DmPayload {
                    kem_ciphertext: Vec::new(),
                    body_nonce: [0u8; 12],
                    body_ciphertext: Vec::new(),
                }),
                signature: Vec::new(),
            },
        };

        let relay_peer = ant_quic::PeerId([0xEE; 32]);
        let relay_wire_sender = [0xEE; 32];
        sender
            .send((relay_peer, relay_wire_sender, relayed))
            .await
            .expect("relayed_dm channel must accept push");

        // Spin until the listener observes the refusal - bounded so a
        // regression fails fast rather than timing out the suite.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let snap = agent.peer_relay().stats().snapshot();
            if snap.relay_refused_bad_signature == 1 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                panic!(
                    "relay-DM listener did not tick relay_refused_bad_signature within 2s - \
                     snapshot: {snap:?}"
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let snap = agent.peer_relay().stats().snapshot();
        assert_eq!(snap.relay_refused_bad_signature, 1);
        assert_eq!(snap.relay_received, 0, "bad-sig path must not deliver");
        assert_eq!(snap.relay_forwarded, 0, "bad-sig path must not forward");
    }

    #[tokio::test]
    async fn agent_creates() {
        let agent = Agent::new().await;
        assert!(agent.is_ok());
    }

    #[tokio::test]
    async fn agent_joins_network() {
        let agent = Agent::new().await.unwrap();
        assert!(agent.join_network().await.is_ok());
    }

    #[tokio::test]
    async fn agent_subscribes() {
        let agent = Agent::new().await.unwrap();
        // Currently returns error - will be implemented in Task 3
        assert!(agent.subscribe("test-topic").await.is_err());
    }

    #[tokio::test]
    async fn identity_announcement_machine_signature_verifies() {
        let agent = Agent::builder()
            .with_network_config(network::NetworkConfig::default())
            .build()
            .await
            .unwrap();

        let announcement = agent.build_identity_announcement(false, false).unwrap();
        assert_eq!(announcement.agent_id, agent.agent_id());
        assert_eq!(announcement.machine_id, agent.machine_id());
        assert!(announcement.user_id.is_none());
        assert!(announcement.agent_certificate.is_none());
        assert!(announcement.verify().is_ok());
    }

    #[tokio::test]
    async fn identity_announcement_requires_human_consent() {
        let agent = Agent::builder()
            .with_network_config(network::NetworkConfig::default())
            .build()
            .await
            .unwrap();

        let err = agent.build_identity_announcement(true, false).unwrap_err();
        assert!(
            err.to_string().contains("explicit human consent"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn identity_announcement_with_user_requires_user_identity() {
        let agent = Agent::builder()
            .with_network_config(network::NetworkConfig::default())
            .build()
            .await
            .unwrap();

        let err = agent.build_identity_announcement(true, true).unwrap_err();
        assert!(
            err.to_string().contains("no user identity is configured"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn announce_identity_populates_discovery_cache() {
        let user_key = identity::UserKeypair::generate().unwrap();
        let agent = Agent::builder()
            .with_network_config(network::NetworkConfig::default())
            .with_user_key(user_key)
            .build()
            .await
            .unwrap();

        agent.announce_identity(true, true).await.unwrap();
        let discovered = agent.discovered_agent(agent.agent_id()).await.unwrap();
        let entry = discovered.expect("agent should discover its own announcement");

        assert_eq!(entry.agent_id, agent.agent_id());
        assert_eq!(entry.machine_id, agent.machine_id());
        assert_eq!(entry.user_id, agent.user_id());
    }

    /// Enforcement point 2 (issue #130): a revoked agent MUST fail
    /// `is_agent_machine_verified` even when its signed identity announcement
    /// is still sitting verified in the discovery cache. This is the DM/gate
    /// denial property — a revoked peer is refused everywhere the daemon asks
    /// "is this (agent, machine) binding trustworthy?". The revocation is
    /// applied via the real `verify_and_insert` receive path (the same call
    /// the gossip subscription makes on receipt), and the subject is
    /// self-revoked (issuer key == subject agent-id, valid authority).
    #[tokio::test]
    async fn revoked_agent_fails_machine_verification_even_when_cached() {
        let user_key = identity::UserKeypair::generate().unwrap();
        let agent = Agent::builder()
            .with_network_config(network::NetworkConfig::default())
            .with_user_key(user_key)
            .build()
            .await
            .unwrap();

        // Seed the discovery cache with our own signed announcement so the
        // (agent, machine) binding verifies true BEFORE revocation.
        agent.announce_identity(true, true).await.unwrap();
        let agent_id = agent.agent_id();
        let machine_id = agent.machine_id();
        assert!(
            agent
                .is_agent_machine_verified(&agent_id, &machine_id)
                .await,
            "a cached, signed self-announcement must verify before revocation"
        );

        // Apply a valid SELF-revocation of our own agent-id via the real
        // receive path. verify_and_insert re-checks the ML-DSA signature and
        // the self-revocation authority rule, exactly as on gossip receipt.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let record = revocation::RevocationRecord::sign(
            revocation::RevokedSubject::Agent(agent_id),
            agent.identity().agent_keypair().public_key(),
            agent.identity().agent_keypair().secret_key(),
            now,
            Some("ep2 test: key compromised".to_string()),
        )
        .unwrap();
        {
            let set = agent.revocation_set();
            let mut set = set.write().await;
            set.verify_and_insert(record, None)
                .expect("self-revocation must verify and insert");
        }

        // Fail-closed: the verified gate must now refuse the revoked agent,
        // even though its announcement is still cached and otherwise valid.
        assert!(
            !agent
                .is_agent_machine_verified(&agent_id, &machine_id)
                .await,
            "a revoked agent must never pass machine verification while cached"
        );
    }

    /// Issue #191 gap 2: a gossiped **issuer-revocation** (a user un-vouching
    /// a certified agent) MUST propagate over gossip. The gossip wire carries
    /// bare `RevocationRecord`s (no certs), so the receiver resolves the
    /// subject cert from its discovery cache — via `collect_subject_certs`,
    /// the exact lookup the gossip-receive loop now performs — and passes it
    /// to `verify_and_insert`. Pre-fix the loop passed `None`, and
    /// `verify_authority` rejects an issuer-revocation without a cert, so only
    /// self-revocations ever propagated network-wide.
    #[test]
    fn issuer_revocation_propagates_over_gossip_via_cache_cert_lookup() {
        let user = identity::UserKeypair::generate().unwrap();
        let issued_agent = identity::AgentKeypair::generate().unwrap();
        let agent_id = issued_agent.agent_id();
        // The user vouches for the agent — this cert is what authorizes a
        // later issuer-revocation (verify_authority checks the issuer key is
        // the certifying user).
        let cert = identity::AgentCertificate::issue(&user, &issued_agent).unwrap();

        // Seed the discovery cache exactly as EP1 does on a real announcement:
        // the cert is retained so a gossiped issuer-revocation can be verified.
        let mut cache = std::collections::HashMap::new();
        cache.insert(
            agent_id,
            DiscoveredAgent {
                agent_id,
                machine_id: identity::MachineId([0u8; 32]),
                user_id: None,
                addresses: Vec::new(),
                announced_at: 0,
                last_seen: 0,
                machine_public_key: Vec::new(),
                nat_type: None,
                can_receive_direct: None,
                is_relay: None,
                is_coordinator: None,
                reachable_via: Vec::new(),
                relay_candidates: Vec::new(),
                cert_not_after: cert.not_after(),
                agent_certificate: Some(cert.clone()),
            },
        );

        // The gossip-receive path resolves subject certs from the cache.
        let subject_certs = collect_subject_certs(&cache);
        let looked_up = subject_certs
            .get(&agent_id)
            .expect("the cache lookup must find the subject cert");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // The user revokes the agent it vouched for (issuer-revocation).
        let record = revocation::RevocationRecord::sign(
            revocation::RevokedSubject::Agent(agent_id),
            user.public_key(),
            user.secret_key(),
            now,
            Some("issuer revokes compromised agent".to_string()),
        )
        .unwrap();

        // With the cache-resolved cert, the issuer-revocation verifies +
        // inserts (the post-fix gossip behavior).
        let mut set = revocation::RevocationSet::new();
        assert!(
            set.verify_and_insert(record.clone(), Some(looked_up))
                .unwrap(),
            "issuer-revocation must verify and insert with the cache-resolved cert"
        );
        assert!(
            set.is_agent_revoked(&agent_id),
            "the agent must now be revoked network-wide"
        );

        // Pre-fix proof: without the cert (the old `None` gossip path), an
        // issuer-revocation is REJECTED by verify_authority — which is exactly
        // why issuer-revocations were inert over gossip before this fix.
        assert!(
            revocation::RevocationSet::new()
                .verify_and_insert(record, None)
                .is_err(),
            "an issuer-revocation must be rejected without the subject cert \
             (the pre-fix gossip behavior this closes)"
        );
    }

    /// An announcement without NAT fields (as produced by old nodes) should still
    /// deserialise correctly via bincode — new fields are `Option` so `None` (0x00)
    /// is a valid encoding.
    #[test]
    fn identity_announcement_backward_compat_no_nat_fields() {
        use identity::{AgentId, MachineId};

        // Build an announcement that omits the nat_* fields by serializing an old-style
        // struct that matches the pre-1.3 wire format.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct OldIdentityAnnouncementUnsigned {
            agent_id: AgentId,
            machine_id: MachineId,
            user_id: Option<identity::UserId>,
            agent_certificate: Option<identity::AgentCertificate>,
            machine_public_key: Vec<u8>,
            addresses: Vec<std::net::SocketAddr>,
            announced_at: u64,
        }

        let agent_id = AgentId([1u8; 32]);
        let machine_id = MachineId([2u8; 32]);
        let old = OldIdentityAnnouncementUnsigned {
            agent_id,
            machine_id,
            user_id: None,
            agent_certificate: None,
            machine_public_key: vec![0u8; 10],
            addresses: Vec::new(),
            announced_at: 1234,
        };
        let bytes = bincode::serialize(&old).expect("serialize old announcement");

        // Attempt to deserialize as the new struct — this tests that the new fields
        // (which are Option<T>) do NOT break deserialization of the old format.
        // Note: bincode 1.x is not self-describing, so adding fields to a struct DOES
        // change the wire format.  This test documents the expected behavior.
        // Old format -> new struct: will fail because new struct has more fields.
        // New format -> old struct: will have trailing bytes.
        // This is acceptable — we document the protocol change.
        let result = bincode::deserialize::<IdentityAnnouncementUnsigned>(&bytes);
        // Old nodes produce shorter messages; new nodes cannot decode them as new structs.
        // This confirms the protocol is not transparent — nodes must upgrade together.
        assert!(
            result.is_err(),
            "Old-format announcement should not decode as new struct (protocol upgrade required)"
        );
    }

    #[tokio::test]
    async fn register_announced_machine_skips_self_agent() {
        // The daemon must never create a contact entry for its own agent: a
        // self record is noise on `/contacts` and makes contact-set
        // assertions racy (issue #145). A self-announcement is refused even
        // though it carries a valid (agent, machine) pair.
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = std::sync::Arc::new(tokio::sync::RwLock::new(contacts::ContactStore::new(
            dir.path().join("contacts.json"),
        )));
        let own = identity::AgentId([1u8; 32]);
        let own_machine = identity::MachineId([2u8; 32]);

        let added = super::register_announced_machine(&store, own, own, own_machine).await;

        assert!(!added, "self-announcement must not register a machine");
        let store = store.read().await;
        assert!(
            store.machines(&own).is_empty(),
            "self-agent must have no machine record after a self-announcement"
        );
        // Stronger invariant: the daemon must have NO contact entry at all
        // for its own agent, not merely an empty machine list. add_machine
        // creates the Contact shell on first sight (contacts.rs:423), so this
        // confirms the self-skip happens before that insertion (#145).
        assert!(
            store.list().iter().all(|contact| contact.agent_id != own),
            "self-agent must not appear in the contact store at all after a \
             self-announcement"
        );
    }

    #[tokio::test]
    async fn register_announced_machine_registers_foreign_agent() {
        // Foreign observation must keep registering a machine record so peers
        // remain observable in the contact surface — the self-skip must not be
        // over-broad. A second announcement of the same (agent, machine) is
        // idempotent (returns false, no duplicate record).
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = std::sync::Arc::new(tokio::sync::RwLock::new(contacts::ContactStore::new(
            dir.path().join("contacts.json"),
        )));
        let own = identity::AgentId([1u8; 32]);
        let peer = identity::AgentId([9u8; 32]);
        let peer_machine = identity::MachineId([7u8; 32]);

        let added = super::register_announced_machine(&store, own, peer, peer_machine).await;
        assert!(added, "foreign announcement must register a new machine");

        let added_again = super::register_announced_machine(&store, own, peer, peer_machine).await;
        assert!(
            !added_again,
            "re-announcing the same machine must be idempotent"
        );

        let store = store.read().await;
        let machines = store.machines(&peer);
        assert_eq!(machines.len(), 1, "exactly one machine record");
        assert_eq!(machines[0].machine_id, peer_machine);
        assert!(
            store.machines(&own).is_empty(),
            "own agent must still have no contact entry"
        );
    }

    #[test]
    fn announcement_assist_snapshot_uses_capabilities_not_activity() {
        let status = ant_quic::NodeStatus {
            nat_type: ant_quic::NatType::FullCone,
            can_receive_direct: true,
            relay_service_enabled: true,
            coordinator_service_enabled: true,
            is_relaying: false,
            is_coordinating: false,
            ..Default::default()
        };

        let snapshot = AnnouncementAssistSnapshot::from_node_status(&status);
        assert_eq!(snapshot.nat_type.as_deref(), Some("Full Cone"));
        assert_eq!(snapshot.can_receive_direct, Some(true));
        assert_eq!(snapshot.relay_capable, Some(true));
        assert_eq!(snapshot.coordinator_capable, Some(true));
        assert_eq!(snapshot.relay_active, Some(false));
        assert_eq!(snapshot.coordinator_active, Some(false));
    }

    /// A new announcement with all NAT fields set round-trips through bincode.
    #[test]
    fn identity_announcement_nat_fields_round_trip() {
        use identity::{AgentId, MachineId};

        let unsigned = IdentityAnnouncementUnsigned {
            agent_id: AgentId([1u8; 32]),
            machine_id: MachineId([2u8; 32]),
            user_id: None,
            agent_certificate: None,
            machine_public_key: vec![0u8; 10],
            addresses: Vec::new(),
            announced_at: 9999,
            nat_type: Some("FullCone".to_string()),
            can_receive_direct: Some(true),
            is_relay: Some(false),
            is_coordinator: Some(true),
            reachable_via: vec![MachineId([5u8; 32])],
            relay_candidates: vec![MachineId([6u8; 32])],
        };
        let bytes = bincode::serialize(&unsigned).expect("serialize");
        let decoded: IdentityAnnouncementUnsigned =
            bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded.nat_type.as_deref(), Some("FullCone"));
        assert_eq!(decoded.can_receive_direct, Some(true));
        assert_eq!(decoded.is_relay, Some(false));
        assert_eq!(decoded.is_coordinator, Some(true));
        assert_eq!(decoded.reachable_via, vec![MachineId([5u8; 32])]);
        assert_eq!(decoded.relay_candidates, vec![MachineId([6u8; 32])]);
    }

    #[tokio::test]
    async fn announcement_decode_helpers_match_bincode_serialize_wire_format() {
        let temp = tempfile::tempdir().unwrap();
        let agent = Agent::builder()
            .with_machine_key(temp.path().join("machine.key"))
            .with_agent_key_path(temp.path().join("agent.key"))
            .with_agent_cert_path(temp.path().join("agent.cert"))
            .with_contact_store_path(temp.path().join("contacts.json"))
            .build()
            .await
            .unwrap();

        let identity = agent.build_identity_announcement(false, false).unwrap();
        let identity_bytes = bincode::serialize(&identity).unwrap();
        let decoded_identity = deserialize_identity_announcement(&identity_bytes).unwrap();
        assert_eq!(decoded_identity.agent_id, identity.agent_id);
        assert_eq!(decoded_identity.machine_id, identity.machine_id);

        let machine = agent.build_machine_announcement().unwrap();
        let machine_bytes = bincode::serialize(&machine).unwrap();
        let decoded_machine = deserialize_machine_announcement(&machine_bytes).unwrap();
        assert_eq!(decoded_machine.machine_id, machine.machine_id);
        assert_eq!(decoded_machine.addresses, machine.addresses);
    }

    #[tokio::test]
    async fn deserialize_identity_announcement_rejects_trailing_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let agent = Agent::builder()
            .with_machine_key(temp.path().join("machine.key"))
            .with_agent_key_path(temp.path().join("agent.key"))
            .with_agent_cert_path(temp.path().join("agent.cert"))
            .with_contact_store_path(temp.path().join("contacts.json"))
            .build()
            .await
            .unwrap();

        let announcement = agent.build_identity_announcement(false, false).unwrap();
        let mut bytes = bincode::serialize(&announcement).unwrap();
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        assert!(
            deserialize_identity_announcement(&bytes).is_err(),
            "identity announcements with trailing bytes must be rejected"
        );
    }

    /// An announcement with None for all NAT fields (e.g. network not started)
    /// round-trips correctly.
    #[test]
    fn identity_announcement_no_nat_fields_round_trip() {
        use identity::{AgentId, MachineId};

        let unsigned = IdentityAnnouncementUnsigned {
            agent_id: AgentId([3u8; 32]),
            machine_id: MachineId([4u8; 32]),
            user_id: None,
            agent_certificate: None,
            machine_public_key: vec![0u8; 10],
            addresses: Vec::new(),
            announced_at: 42,
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
        };
        let bytes = bincode::serialize(&unsigned).expect("serialize");
        let decoded: IdentityAnnouncementUnsigned =
            bincode::deserialize(&bytes).expect("deserialize");
        assert!(decoded.nat_type.is_none());
        assert!(decoded.can_receive_direct.is_none());
        assert!(decoded.is_relay.is_none());
        assert!(decoded.is_coordinator.is_none());
        assert!(decoded.reachable_via.is_empty());
        assert!(decoded.relay_candidates.is_empty());
    }

    /// Wire format v2 populates coordinator-hint fields: full round-trip and
    /// deterministic signing.
    #[test]
    fn identity_announcement_reachable_via_round_trip() {
        use identity::{AgentId, MachineId};

        let coord_a = MachineId([0xAAu8; 32]);
        let coord_b = MachineId([0xBBu8; 32]);
        let unsigned = IdentityAnnouncementUnsigned {
            agent_id: AgentId([9u8; 32]),
            machine_id: MachineId([8u8; 32]),
            user_id: None,
            agent_certificate: None,
            machine_public_key: vec![0u8; 10],
            addresses: Vec::new(),
            announced_at: 555,
            nat_type: Some("Symmetric".to_string()),
            can_receive_direct: Some(false),
            is_relay: Some(false),
            is_coordinator: Some(false),
            reachable_via: vec![coord_a, coord_b],
            relay_candidates: vec![coord_a],
        };
        let bytes = bincode::serialize(&unsigned).expect("serialize");
        let decoded: IdentityAnnouncementUnsigned =
            bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded.reachable_via, vec![coord_a, coord_b]);
        assert_eq!(decoded.relay_candidates, vec![coord_a]);

        // Mutating reachable_via MUST invalidate the outer sig — signing over
        // the unsigned form guarantees integrity. Here we only verify the
        // bincode is stable; cryptographic coverage lives in the existing
        // `identity_announcement_machine_signature_verifies` tests.
        let re_encoded = bincode::serialize(&decoded).expect("re-serialize");
        assert_eq!(
            bytes, re_encoded,
            "canonical bincode round-trip must be stable"
        );
    }

    #[test]
    fn user_announcement_sign_and_verify() {
        let user_kp = identity::UserKeypair::generate().unwrap();
        let agent_kp_a = identity::AgentKeypair::generate().unwrap();
        let agent_kp_b = identity::AgentKeypair::generate().unwrap();
        let cert_a = identity::AgentCertificate::issue(&user_kp, &agent_kp_a).unwrap();
        let cert_b = identity::AgentCertificate::issue(&user_kp, &agent_kp_b).unwrap();

        let announcement = UserAnnouncement::sign(&user_kp, vec![cert_a, cert_b], 1234).unwrap();
        announcement.verify().expect("freshly-signed must verify");
        assert_eq!(announcement.user_id, user_kp.user_id());
        assert_eq!(announcement.agent_certificates.len(), 2);
    }

    #[test]
    fn deserialize_user_announcement_rejects_trailing_bytes() {
        let user_kp = identity::UserKeypair::generate().unwrap();
        let agent_kp = identity::AgentKeypair::generate().unwrap();
        let cert = identity::AgentCertificate::issue(&user_kp, &agent_kp).unwrap();
        let announcement = UserAnnouncement::sign(&user_kp, vec![cert], 1234).unwrap();
        let mut bytes = bincode::serialize(&announcement).unwrap();
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        assert!(
            deserialize_user_announcement(&bytes).is_err(),
            "user announcements with trailing bytes must be rejected"
        );
    }

    #[test]
    fn user_announcement_rejects_foreign_certificate() {
        let user_kp = identity::UserKeypair::generate().unwrap();
        let other_user = identity::UserKeypair::generate().unwrap();
        let agent_kp = identity::AgentKeypair::generate().unwrap();
        // Certificate issued by `other_user` — we should refuse to include it
        // in a roster signed by `user_kp`.
        let foreign_cert = identity::AgentCertificate::issue(&other_user, &agent_kp).unwrap();
        let err = UserAnnouncement::sign(&user_kp, vec![foreign_cert], 0).unwrap_err();
        assert!(
            err.to_string().contains("different user"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn user_announcement_tampered_agent_cert_list_fails() {
        let user_kp = identity::UserKeypair::generate().unwrap();
        let agent_kp = identity::AgentKeypair::generate().unwrap();
        let cert = identity::AgentCertificate::issue(&user_kp, &agent_kp).unwrap();

        let mut announcement = UserAnnouncement::sign(&user_kp, vec![cert], 10).unwrap();
        // Forge an additional certificate from a different user into the list.
        let other_user = identity::UserKeypair::generate().unwrap();
        let other_agent = identity::AgentKeypair::generate().unwrap();
        let foreign_cert = identity::AgentCertificate::issue(&other_user, &other_agent).unwrap();
        announcement.agent_certificates.push(foreign_cert);
        assert!(
            announcement.verify().is_err(),
            "announcement with appended foreign cert must fail verification"
        );
    }

    #[test]
    fn user_announcement_tampered_user_public_key_fails() {
        let user_kp = identity::UserKeypair::generate().unwrap();
        let agent_kp = identity::AgentKeypair::generate().unwrap();
        let cert = identity::AgentCertificate::issue(&user_kp, &agent_kp).unwrap();
        let mut announcement = UserAnnouncement::sign(&user_kp, vec![cert], 10).unwrap();
        let other = identity::UserKeypair::generate().unwrap();
        announcement.user_public_key = other.public_key().as_bytes().to_vec();
        assert!(announcement.verify().is_err());
    }

    #[test]
    fn user_shard_topic_is_deterministic() {
        let user_id = identity::UserId([5u8; 32]);
        let topic_a = shard_topic_for_user(&user_id);
        let topic_b = shard_topic_for_user(&user_id);
        assert_eq!(topic_a, topic_b);
        assert!(topic_a.starts_with("x0x.user.shard.v2."));
    }
}
#[test]
fn agent_shard_topic_is_deterministic() {
    let agent_id = identity::AgentId([6u8; 32]);
    let topic_a = shard_topic_for_agent(&agent_id);
    let topic_b = shard_topic_for_agent(&agent_id);
    assert_eq!(topic_a, topic_b);
    assert!(topic_a.starts_with("x0x.identity.shard.v2."));
}

#[test]
fn machine_shard_topic_is_deterministic() {
    let machine_id = identity::MachineId([7u8; 32]);
    let topic_a = shard_topic_for_machine(&machine_id);
    let topic_b = shard_topic_for_machine(&machine_id);
    assert_eq!(topic_a, topic_b);
    assert!(topic_a.starts_with("x0x.machine.shard.v2."));
}

#[test]
fn rendezvous_shard_topic_is_deterministic() {
    let agent_id = identity::AgentId([8u8; 32]);
    let topic_a = rendezvous_shard_topic_for_agent(&agent_id);
    let topic_b = rendezvous_shard_topic_for_agent(&agent_id);
    assert_eq!(topic_a, topic_b);
    assert!(topic_a.starts_with("x0x.rendezvous.shard."));
}

#[test]
fn different_ids_produce_different_shard_topics() {
    let agent_a = identity::AgentId([1u8; 32]);
    let agent_b = identity::AgentId([2u8; 32]);
    let topic_a = shard_topic_for_agent(&agent_a);
    let topic_b = shard_topic_for_agent(&agent_b);
    assert_ne!(
        topic_a, topic_b,
        "different agent IDs should produce different shard topics"
    );
}

#[test]
fn collect_local_interface_addrs_returns_non_empty() {
    let addrs = collect_local_interface_addrs(5483);
    assert!(!addrs.is_empty(), "should find at least one interface");
    for addr in &addrs {
        assert_eq!(addr.port(), 5483, "all addrs should use port 5483");
    }
}

#[test]
fn collect_local_interface_addrs_returns_reasonable_results() {
    let addrs = collect_local_interface_addrs(9000);
    assert!(!addrs.is_empty(), "should find at least one interface");
    for addr in &addrs {
        assert_eq!(addr.port(), 9000, "all addrs should use port 9000");
    }
}

#[test]
fn is_globally_routable_v4_private() {
    assert!(!is_globally_routable(std::net::IpAddr::V4(
        std::net::Ipv4Addr::new(10, 0, 0, 1)
    )));
    assert!(!is_globally_routable(std::net::IpAddr::V4(
        std::net::Ipv4Addr::new(172, 16, 0, 1)
    )));
    assert!(!is_globally_routable(std::net::IpAddr::V4(
        std::net::Ipv4Addr::new(192, 168, 1, 1)
    )));
}

#[test]
fn is_globally_routable_v4_global() {
    assert!(is_globally_routable(std::net::IpAddr::V4(
        std::net::Ipv4Addr::new(8, 8, 8, 8)
    )));
    assert!(is_globally_routable(std::net::IpAddr::V4(
        std::net::Ipv4Addr::new(1, 2, 3, 4)
    )));
}

#[test]
fn is_globally_routable_v6_private() {
    assert!(!is_globally_routable(std::net::IpAddr::V6(
        std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)
    )));
    assert!(!is_globally_routable(std::net::IpAddr::V6(
        std::net::Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)
    )));
    assert!(!is_globally_routable(std::net::IpAddr::V6(
        std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)
    )));
}

#[test]
fn is_globally_routable_v6_global() {
    assert!(is_globally_routable(std::net::IpAddr::V6(
        std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
    )));
    assert!(is_globally_routable(std::net::IpAddr::V6(
        std::net::Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)
    )));
}

#[test]
fn is_globally_routable_v4_cgnat() {
    assert!(!is_globally_routable(std::net::IpAddr::V4(
        std::net::Ipv4Addr::new(100, 64, 0, 1)
    )));
    assert!(!is_globally_routable(std::net::IpAddr::V4(
        std::net::Ipv4Addr::new(100, 127, 255, 255)
    )));
}

#[test]
fn is_globally_routable_v4_documentation() {
    assert!(!is_globally_routable(std::net::IpAddr::V4(
        std::net::Ipv4Addr::new(192, 0, 2, 1)
    )));
    assert!(!is_globally_routable(std::net::IpAddr::V4(
        std::net::Ipv4Addr::new(198, 51, 100, 1)
    )));
    assert!(!is_globally_routable(std::net::IpAddr::V4(
        std::net::Ipv4Addr::new(203, 0, 113, 1)
    )));
}

#[test]
fn is_globally_routable_v4_broadcast() {
    assert!(!is_globally_routable(std::net::IpAddr::V4(
        std::net::Ipv4Addr::new(255, 255, 255, 255)
    )));
}

#[test]
fn is_globally_routable_v4_unspecified() {
    assert!(!is_globally_routable(std::net::IpAddr::V4(
        std::net::Ipv4Addr::new(0, 0, 0, 0)
    )));
}

#[test]
fn is_globally_routable_v6_unspecified() {
    assert!(!is_globally_routable(std::net::IpAddr::V6(
        std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)
    )));
}

#[test]
fn is_globally_routable_v6_unique_local() {
    assert!(!is_globally_routable(std::net::IpAddr::V6(
        std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)
    )));
}

#[test]
fn is_globally_routable_v6_site_local() {
    assert!(!is_globally_routable(std::net::IpAddr::V6(
        std::net::Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 1)
    )));
}

#[test]
fn push_unique_adds_new_item() {
    let mut items = vec![1, 2, 3];
    push_unique(&mut items, 4);
    assert_eq!(items, vec![1, 2, 3, 4]);
}

#[test]
fn push_unique_skips_existing_item() {
    let mut items = vec![1, 2, 3];
    push_unique(&mut items, 2);
    assert_eq!(items, vec![1, 2, 3]);
}

#[test]
fn push_unique_works_with_empty() {
    let mut items: Vec<i32> = vec![];
    push_unique(&mut items, 42);
    assert_eq!(items, vec![42]);
}

#[cfg(test)]
fn discovered_agent_fixture(
    tag: u8,
    announced_at: u64,
    addrs: &[&str],
    user_id: Option<identity::UserId>,
) -> DiscoveredAgent {
    DiscoveredAgent {
        agent_id: identity::AgentId([tag; 32]),
        machine_id: identity::MachineId([tag; 32]),
        user_id,
        addresses: addrs
            .iter()
            .map(|a| a.parse().expect("valid socket addr"))
            .collect(),
        announced_at,
        last_seen: announced_at,
        machine_public_key: vec![tag],
        nat_type: None,
        can_receive_direct: None,
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: None,
    }
}

#[tokio::test]
async fn upsert_discovered_agent_replaces_addresses_on_fresher_announcement() {
    let cache = std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    let id = identity::AgentId([7; 32]);

    upsert_discovered_agent(
        &cache,
        discovered_agent_fixture(7, 100, &["10.0.0.1:5483", "8.8.8.8:5483"], None),
    )
    .await;
    // A fresher announcement advertising a NEW address set must REPLACE, not
    // accumulate — otherwise a roaming agent grows an unbounded list of dead
    // endpoints that each cost a dial timeout.
    upsert_discovered_agent(
        &cache,
        discovered_agent_fixture(7, 200, &["1.2.3.4:5483"], None),
    )
    .await;

    let guard = cache.read().await;
    let entry = guard.get(&id).expect("entry present");
    assert_eq!(
        entry.addresses,
        vec!["1.2.3.4:5483".parse().expect("addr")],
        "fresher announcement must replace the address set, not union it"
    );
}

#[tokio::test]
async fn upsert_discovered_agent_ignores_stale_announcement_addresses() {
    let cache = std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    let id = identity::AgentId([8; 32]);

    upsert_discovered_agent(
        &cache,
        discovered_agent_fixture(8, 200, &["1.2.3.4:5483"], None),
    )
    .await;
    // A stale (lower announced_at) announcement must not inject its old
    // addresses into the fresher cached record.
    upsert_discovered_agent(
        &cache,
        discovered_agent_fixture(8, 100, &["10.0.0.9:5483"], None),
    )
    .await;

    let guard = cache.read().await;
    let entry = guard.get(&id).expect("entry present");
    assert_eq!(
        entry.addresses,
        vec!["1.2.3.4:5483".parse().expect("addr")],
        "stale announcement must not add addresses"
    );
    assert_eq!(
        entry.announced_at, 200,
        "stale announcement must not regress announced_at"
    );
}

#[tokio::test]
async fn upsert_discovered_agent_preserves_known_user_id() {
    let cache = std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    let id = identity::AgentId([9; 32]);
    let user = identity::UserId([9; 32]);

    upsert_discovered_agent(
        &cache,
        discovered_agent_fixture(9, 100, &["1.2.3.4:5483"], Some(user)),
    )
    .await;
    // A fresher but anonymous announcement must not erase a known user_id.
    upsert_discovered_agent(
        &cache,
        discovered_agent_fixture(9, 200, &["1.2.3.4:5483"], None),
    )
    .await;

    let guard = cache.read().await;
    let entry = guard.get(&id).expect("entry present");
    assert_eq!(
        entry.user_id,
        Some(user),
        "a fresher anonymous announcement must not erase a disclosed user_id"
    );
}

#[test]
fn sort_discovered_machine_sorts_fields() {
    let mut machine = DiscoveredMachine {
        machine_id: identity::MachineId([3u8; 32]),
        addresses: vec![
            "10.0.0.2:5483".parse::<std::net::SocketAddr>().unwrap(),
            "10.0.0.1:5483".parse::<std::net::SocketAddr>().unwrap(),
        ],
        announced_at: 100,
        last_seen: 100,
        machine_public_key: vec![],
        nat_type: None,
        can_receive_direct: None,
        is_relay: None,
        is_coordinator: None,
        reachable_via: vec![
            identity::MachineId([2u8; 32]),
            identity::MachineId([1u8; 32]),
        ],
        relay_candidates: vec![
            identity::MachineId([4u8; 32]),
            identity::MachineId([3u8; 32]),
        ],
        agent_ids: vec![identity::AgentId([2u8; 32]), identity::AgentId([1u8; 32])],
        user_ids: vec![identity::UserId([2u8; 32]), identity::UserId([1u8; 32])],
    };
    sort_discovered_machine(&mut machine);
    assert_eq!(
        machine.addresses[0],
        "10.0.0.1:5483".parse::<std::net::SocketAddr>().unwrap()
    );
    assert_eq!(
        machine.addresses[1],
        "10.0.0.2:5483".parse::<std::net::SocketAddr>().unwrap()
    );
    assert_eq!(machine.reachable_via[0], identity::MachineId([1u8; 32]));
    assert_eq!(machine.reachable_via[1], identity::MachineId([2u8; 32]));
    assert_eq!(machine.relay_candidates[0], identity::MachineId([3u8; 32]));
    assert_eq!(machine.relay_candidates[1], identity::MachineId([4u8; 32]));
    assert_eq!(machine.agent_ids[0], identity::AgentId([1u8; 32]));
    assert_eq!(machine.agent_ids[1], identity::AgentId([2u8; 32]));
    assert_eq!(machine.user_ids[0], identity::UserId([1u8; 32]));
    assert_eq!(machine.user_ids[1], identity::UserId([2u8; 32]));
}

#[tokio::test]
async fn dm_inbox_capability_upgrade_visible_to_late_subscriber() {
    // Regression test for issue #101: x0xd starts the DM inbox before the
    // capability advert service subscribes to the capabilities watch. The
    // upgrade must be stored in the channel (send_replace), not merely
    // broadcast to current receivers (send) — otherwise a late subscriber
    // observes the stale pending state, advertises gossip_inbox=false for
    // the process lifetime, and cross-NAT DMs fall back to the raw-QUIC
    // path that black-holes.
    let dir = tempfile::tempdir().expect("tmpdir");
    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_peer_cache_dir(dir.path().join("peers"))
        .with_network_config(network::NetworkConfig::default())
        .build()
        .await
        .expect("agent");

    let kem = std::sync::Arc::new(
        groups::kem_envelope::AgentKemKeypair::generate().expect("kem keypair"),
    );
    agent
        .start_dm_inbox(kem, dm_inbox::DmInboxConfig::default())
        .await
        .expect("start dm inbox");

    // Subscribe only AFTER the inbox started — mirrors the x0xd startup
    // order (start_dm_inbox_when_gossip_ready runs before
    // start_capability_advert_service).
    let late_rx = agent.dm_capabilities_tx.subscribe();
    let caps = late_rx.borrow().clone();
    assert!(
        caps.gossip_inbox,
        "DM capability upgrade must be visible to subscribers that attach after start_dm_inbox (issue #101)"
    );
    assert!(
        !caps.kem_public_key.is_empty(),
        "upgraded capabilities must carry the KEM public key"
    );
    agent.stop_dm_inbox().await;
}

#[test]
fn deserialize_identity_announcement_rejects_empty() {
    let result = deserialize_identity_announcement(&[]);
    assert!(result.is_err());
}

#[test]
fn deserialize_machine_announcement_rejects_empty() {
    let result = deserialize_machine_announcement(&[]);
    assert!(result.is_err());
}

#[test]
fn deserialize_identity_announcement_rejects_garbage() {
    let result = deserialize_identity_announcement(b"not-a-valid-bincode");
    assert!(result.is_err());
}

#[test]
fn deserialize_machine_announcement_rejects_garbage() {
    let result = deserialize_machine_announcement(b"not-a-valid-bincode");
    assert!(result.is_err());
}
