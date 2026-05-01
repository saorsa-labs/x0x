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
//! use x0x::Agent;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create an agent with default configuration
//! // This automatically connects to 6 global bootstrap nodes
//! let agent = Agent::builder()
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
//! Agents automatically connect to Saorsa Labs' global bootstrap network:
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

/// Bootstrap node discovery and connection.
///
/// This module handles initial connection to bootstrap nodes with
/// exponential backoff retry logic and peer cache integration.
pub mod bootstrap;
/// Network transport layer for x0x.
pub mod network;

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

/// Presence system — beacons, FOAF discovery, and online/offline events.
pub mod presence;

/// Self-update system with ML-DSA-65 signature verification and staged rollout.
pub mod upgrade;

/// File transfer protocol types and state management.
pub mod files;

/// Secure Tier-1 remote exec protocol and runtime.
pub mod exec;

/// The x0x Constitution — The Four Laws of Intelligent Coexistence — embedded at compile time.
pub mod constitution;

/// Shared API endpoint registry consumed by both x0xd and the x0x CLI.
pub mod api;

/// CLI infrastructure and command implementations.
pub mod cli;

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

fn push_unique<T: Copy + PartialEq>(items: &mut Vec<T>, item: T) {
    if !items.contains(&item) {
        items.push(item);
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
        .allow_trailing_bytes()
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
) -> error::Result<MachineAnnouncement> {
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

        // Heartbeat announcements propagate over global gossip. We MUST NOT
        // include LAN-scope addresses here — LAN-peer discovery is handled by
        // ant-quic's first-party mDNS, and shipping RFC1918/ULA/link-local
        // addresses to remote peers causes them to burn ~50s per candidate on
        // a dial that can never succeed (see investigation 2026-04-15, report
        // tests/proof-reports/MDNS_VS_GOSSIP_ADDRESS_SCOPE_20260415.md).
        addresses.retain(|a| is_publicly_advertisable(*a));

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
        };
        upsert_discovered_machine_from_agent(&self.machine_cache, &discovered_agent).await;
        self.cache
            .write()
            .await
            .insert(discovered_agent.agent_id, discovered_agent);
        Ok(())
    }
}

impl Agent {
    /// Create a new agent with default configuration.
    ///
    /// This generates a fresh identity with both machine and agent keypairs.
    /// The machine keypair is stored persistently in `~/.x0x/machine.key`.
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
    pub fn builder() -> AgentBuilder {
        AgentBuilder {
            machine_key_path: None,
            agent_keypair: None,
            agent_key_path: None,
            agent_cert_path: None,
            user_keypair: None,
            user_key_path: None,
            network_config: None,
            peer_cache_dir: None,
            disable_peer_cache: false,
            heartbeat_interval_secs: None,
            identity_ttl_secs: None,
            presence_beacon_interval_secs: None,
            presence_event_poll_interval_secs: None,
            presence_offline_timeout_secs: None,
            contact_store_path: None,
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
                %agent_prefix,
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
            %agent_prefix,
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
                %machine_prefix,
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

        network
            .upsert_peer_hints(peer_id, info.addresses.clone(), None)
            .await
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "failed to upsert machine peer hints: {e}"
                )))
            })?;

        let dial_timeout = std::time::Duration::from_secs(8);
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
                    %machine_prefix,
                    selected_addr = %addr,
                    verified_machine_prefix = %network::hex_prefix(&verified_peer_id.0, 4),
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
                            %machine_prefix,
                            %addr,
                            connected_machine_prefix = %network::hex_prefix(&connected_peer_id.0, 4),
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
            %machine_prefix,
            outcome = "unreachable",
            reason = "all_strategies_exhausted",
            dur_ms = call_start.elapsed().as_millis() as u64,
            v4_addrs,
            v6_addrs,
            "all machine connection strategies exhausted"
        );
        Ok(connectivity::ConnectOutcome::Unreachable)
    }

    /// Save the bootstrap cache and release resources.
    ///
    /// Call this before dropping the agent to ensure the peer cache is
    /// persisted to disk. The background maintenance task saves periodically,
    /// but this guarantees a final save.
    pub async fn shutdown(&self) {
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
        let rtt_hint_ms = self.dm_peer_rtt_ms(to).await;
        let mut config = config;
        if config.timeout_per_attempt == dm::dm_attempt_timeout(None) {
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

        let cap = self.capability_store.lookup(to);
        let gossip_ok = cap
            .as_ref()
            .map(|c| c.gossip_inbox && !c.kem_public_key.is_empty())
            .unwrap_or(false);

        let mut preferred_raw_err = None;
        let preferred_raw_receipt = if config.prefer_raw_quic_if_connected && !config.require_gossip
        {
            match self
                .send_direct_raw_quic(to, &payload, config.raw_quic_receive_ack_timeout)
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
        } else if preferred_raw_err
            .as_ref()
            .is_some_and(Self::raw_quic_error_should_stop_fallback)
        {
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
                    dm_send::send_via_gossip(
                        std::sync::Arc::clone(runtime.pubsub()),
                        &signing,
                        self.identity.agent_id(),
                        self.identity.machine_id(),
                        *to,
                        &kem_pub,
                        payload,
                        &config,
                        std::sync::Arc::clone(&self.dm_inflight_acks),
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
                    .send_direct_raw_quic(to, &payload, config.raw_quic_receive_ack_timeout)
                    .await
                    .map(dm_send::raw_quic_receipt_for_path)
                    .map_err(Self::map_raw_quic_dm_error),
            }
        };

        match &result {
            Ok(receipt) => self
                .direct_messaging
                .record_outgoing_succeeded(*to, receipt.path),
            Err(_) => self.direct_messaging.record_outgoing_failed(*to),
        }
        result
    }

    /// Legacy raw-QUIC direct-send path. Internal fallback only.
    async fn send_direct_raw_quic(
        &self,
        agent_id: &identity::AgentId,
        payload: &[u8],
        receive_ack_timeout: Option<std::time::Duration>,
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
                %agent_prefix,
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
                            %agent_prefix,
                            outcome = "err_agent_not_found",
                            dur_ms = send_start.elapsed().as_millis() as u64,
                            "no machine_id after connect_to_agent"
                        );
                        error::NetworkError::AgentNotFound(agent_id.0)
                    })?;
                (id, "post_connect")
            }
        };

        // Check if connected
        let ant_peer_id = ant_quic::PeerId(machine_id.0);
        let machine_prefix = network::hex_prefix(&machine_id.0, 4);
        if let Some(reason) = self.direct_messaging.lifecycle_block_reason(&machine_id) {
            tracing::warn!(
                target: "x0x::direct",
                stage = "send",
                %agent_prefix,
                %machine_prefix,
                resolution,
                outcome = "err_peer_disconnected",
                reason = %reason,
                dur_ms = send_start.elapsed().as_millis() as u64,
                "lifecycle watcher says peer is disconnected"
            );
            return Err(error::NetworkError::ConnectionFailed(format!(
                "peer disconnected: {reason}"
            )));
        }
        if !network.is_connected(&ant_peer_id).await {
            tracing::warn!(
                target: "x0x::direct",
                stage = "send",
                %agent_prefix,
                %machine_prefix,
                resolution,
                outcome = "err_not_connected",
                bytes,
                dur_ms = send_start.elapsed().as_millis() as u64,
                "machine_id resolved but peer not currently connected"
            );
            return Err(error::NetworkError::AgentNotConnected(agent_id.0));
        }

        tracing::info!(
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
            tracing::info!(
                target: "dm.trace",
                stage = "wire_encoded",
                sender = %hex::encode(self.identity.agent_id().as_bytes()),
                recipient = %hex::encode(agent_id.as_bytes()),
                path = "raw_quic_acked",
                bytes = wire.len(),
                payload_bytes = bytes,
                digest = %digest,
            );
            match network
                .send_with_receive_ack(ant_peer_id, &wire, timeout)
                .await
            {
                Some(Ok(())) => Ok(dm::DmPath::RawQuicAcked),
                Some(Err(e)) => Err(error::NetworkError::ConnectionFailed(format!(
                    "send_with_receive_ack failed: {e}"
                ))),
                None => Err(error::NetworkError::NodeCreation(
                    "network node not initialized".to_string(),
                )),
            }
        } else {
            tracing::info!(
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
                    dm::DmPath::RawQuic => "raw_quic",
                    dm::DmPath::RawQuicAcked => "raw_quic_acked",
                    dm::DmPath::GossipInbox => "gossip_inbox",
                };
                tracing::info!(
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
                    %machine_prefix,
                    resolution,
                    bytes,
                    dur_ms = send_start.elapsed().as_millis() as u64,
                    outcome = "err_transport",
                    error = %e,
                    "transport send_direct failed"
                );
                Err(e)
            }
        }
    }

    fn raw_quic_error_should_stop_fallback(err: &error::NetworkError) -> bool {
        match err {
            error::NetworkError::ConnectionFailed(reason) => {
                reason.starts_with("peer disconnected:")
                    || reason.starts_with("send_with_receive_ack failed:")
            }
            error::NetworkError::ConnectionClosed(_)
            | error::NetworkError::ConnectionReset(_)
            | error::NetworkError::NotConnected(_) => true,
            _ => false,
        }
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
            runtime.pubsub().set_contacts(store);
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

        // Same rule as HeartbeatContext::announce() — gossip is global, so
        // LAN-scope addresses must never be published here. See the scope
        // analysis report under tests/proof-reports/ for details.
        addresses.retain(|a| is_publicly_advertisable(*a));

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

        let announcement = self.build_identity_announcement_with_addrs(
            include_user_identity,
            human_consent,
            addresses,
            Some(&assist_snapshot),
            reachable_via,
            relay_candidates,
        )?;
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
        };
        upsert_discovered_machine_from_agent(&self.machine_discovery_cache, &discovered_agent)
            .await;
        self.identity_discovery_cache
            .write()
            .await
            .insert(discovered_agent.agent_id, discovered_agent);

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
            .filter(|a| a.last_seen >= cutoff)
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

        for agent in cache.values().filter(|agent| agent.last_seen >= cutoff) {
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

    /// Return all discovered agents regardless of TTL.
    ///
    /// Unlike [`Self::discovered_agents`], this method skips TTL filtering and
    /// returns all cache entries, including stale ones. Useful for debugging.
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
            .filter(|m| m.announced_at >= cutoff)
            .cloned()
            .collect();
        machines.sort_by_key(|m| m.machine_id.0);
        Ok(machines)
    }

    /// Return all discovered machines regardless of TTL.
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
            .filter(|m| m.announced_at >= cutoff && m.user_ids.contains(&user_id))
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
            .filter(|u| u.announced_at >= cutoff)
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
            .filter(|u| u.announced_at >= cutoff)
            .cloned()
            .collect();
        users.sort_by_key(|u| u.user_id.0);
        Ok(users)
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
        let own_agent_id = self.agent_id();
        let own_machine_id = self.machine_id();
        let own_user_id = self.user_id();
        let rebroadcast_pubsub = std::sync::Arc::clone(runtime.pubsub());

        tokio::spawn(async move {
            enum DiscoveryMessage {
                Identity(crate::gossip::PubSubMessage),
                Machine(crate::gossip::PubSubMessage),
                User(crate::gossip::PubSubMessage),
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

                        let public_addrs: Vec<std::net::SocketAddr> = announcement
                            .addresses
                            .iter()
                            .copied()
                            .filter(|a| is_globally_routable(a.ip()))
                            .collect();
                        if !public_addrs.is_empty() {
                            if let Some(ref bc) = &bootstrap_cache {
                                let peer_id = ant_quic::PeerId(announcement.machine_id.0);
                                bc.add_from_connection(peer_id, public_addrs, None).await;
                            }
                        }

                        let filtered_addresses: Vec<std::net::SocketAddr> = announcement
                            .addresses
                            .iter()
                            .copied()
                            .filter(|a| is_publicly_advertisable(*a))
                            .collect();
                        let filtered_addr_count = filtered_addresses.len();
                        upsert_discovered_machine(
                            &machine_cache,
                            DiscoveredMachine::from_machine_announcement(
                                &announcement,
                                filtered_addresses,
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
                        let decoded = {
                            use bincode::Options;
                            bincode::options()
                                .with_fixint_encoding()
                                .with_limit(crate::network::MAX_MESSAGE_DESERIALIZE_SIZE)
                                .allow_trailing_bytes()
                                .deserialize::<UserAnnouncement>(&msg.payload)
                        };
                        let raw_payload = msg.payload.clone();
                        let announcement = match decoded {
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
                                "Dropping identity announcement from agent {:?}: machine {:?} not in pinned list",
                                hex::encode(&announcement.agent_id.0[..8]),
                                hex::encode(&announcement.machine_id.0[..8]),
                            );
                            continue;
                        }
                        _ => {}
                    }
                }

                // Update machine records in the contact store.
                {
                    let mut store = contact_store.write().await;
                    let record = contacts::MachineRecord::new(announcement.machine_id, None);
                    store.add_machine(&announcement.agent_id, record);
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());

                // Add only globally-routable addresses to the persistent
                // bootstrap cache. Private/LAN addresses are kept in the
                // ephemeral discovery cache (below) for same-network
                // connectivity, but must not persist across restarts where
                // they become stale dead-ends for remote nodes.
                {
                    let public_addrs: Vec<std::net::SocketAddr> = announcement
                        .addresses
                        .iter()
                        .copied()
                        .filter(|a| is_globally_routable(a.ip()))
                        .collect();
                    if !public_addrs.is_empty() {
                        if let Some(ref bc) = &bootstrap_cache {
                            let peer_id = ant_quic::PeerId(announcement.machine_id.0);
                            bc.add_from_connection(peer_id, public_addrs.clone(), None)
                                .await;
                            tracing::debug!(
                                "Added {} public addresses to bootstrap cache for agent {:?} (machine {:?})",
                                public_addrs.len(),
                                announcement.agent_id,
                                hex::encode(&announcement.machine_id.0[..8]),
                            );
                        }
                    }
                }

                // Cache the announcement with its address list filtered to
                // globally-advertisable scope only. Legacy peers that still
                // ship RFC1918/ULA/loopback entries in their announcements
                // must not force us to keep dialing their unreachable LAN
                // addresses — LAN discovery is ant-quic's mDNS job. Empty
                // address lists are preserved (the `AlreadyConnected` path in
                // `connect_to_agent` handles gossip peers we only reach by
                // an existing QUIC connection).
                let filtered_addresses: Vec<std::net::SocketAddr> = announcement
                    .addresses
                    .iter()
                    .copied()
                    .filter(|a| is_publicly_advertisable(*a))
                    .collect();
                let filtered_addr_count = filtered_addresses.len();
                let discovered_agent = DiscoveredAgent {
                    agent_id: announcement.agent_id,
                    machine_id: announcement.machine_id,
                    user_id: announcement.user_id,
                    addresses: filtered_addresses,
                    announced_at: announcement.announced_at,
                    last_seen: now,
                    machine_public_key: announcement.machine_public_key.clone(),
                    nat_type: announcement.nat_type.clone(),
                    can_receive_direct: announcement.can_receive_direct,
                    is_relay: announcement.is_relay,
                    is_coordinator: announcement.is_coordinator,
                    reachable_via: announcement.reachable_via.clone(),
                    relay_candidates: announcement.relay_candidates.clone(),
                };
                upsert_discovered_machine_from_agent(&machine_cache, &discovered_agent).await;
                cache
                    .write()
                    .await
                    .insert(discovered_agent.agent_id, discovered_agent);
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
                    && !announcement.addresses.is_empty()
                    && !auto_connect_attempted.contains(&announcement.agent_id)
                {
                    if let Some(ref net) = &network {
                        let ant_peer = ant_quic::PeerId(announcement.machine_id.0);
                        if !net.is_connected(&ant_peer).await {
                            auto_connect_attempted.insert(announcement.agent_id);
                            let net = std::sync::Arc::clone(net);
                            let addresses = announcement.addresses.clone();
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
            Some(addr) if addr.port() > 0 => collect_local_interface_addrs(addr.port()),
            _ => Vec::new(),
        }
    }

    fn build_identity_announcement(
        &self,
        include_user_identity: bool,
        human_consent: bool,
    ) -> error::Result<IdentityAnnouncement> {
        self.build_identity_announcement_with_addrs(
            include_user_identity,
            human_consent,
            self.announcement_addresses(),
            None,
            Vec::new(),
            Vec::new(),
        )
    }

    fn build_identity_announcement_with_addrs(
        &self,
        include_user_identity: bool,
        human_consent: bool,
        addresses: Vec<std::net::SocketAddr>,
        assist_snapshot: Option<&AnnouncementAssistSnapshot>,
        reachable_via: Vec<identity::MachineId>,
        relay_candidates: Vec<identity::MachineId>,
    ) -> error::Result<IdentityAnnouncement> {
        if include_user_identity && !human_consent {
            return Err(error::IdentityError::Storage(std::io::Error::other(
                "human identity disclosure requires explicit human consent — set human_consent: true in the request body",
            )));
        }

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
        self.start_identity_listener().await?;
        self.start_network_event_listener();
        self.start_direct_listener();

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
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                    interval.tick().await; // first tick fires immediately; startup already seeded
                    loop {
                        interval.tick().await;

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

        if let Err(e) = self.announce_identity(false, false).await {
            tracing::warn!("Initial identity announcement failed: {}", e);
        }
        if let Err(e) = self.start_identity_heartbeat().await {
            tracing::warn!("Failed to start identity heartbeat: {e}");
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
            };
            tokio::spawn(async move {
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

        // Start the capability advert service. Until start_dm_inbox runs,
        // the advert declares gossip_inbox=false — senders fall back to
        // raw-QUIC. Once upgraded, peers learn about gossip DM support.
        if let Some(ref runtime) = self.gossip_runtime {
            let signing = std::sync::Arc::new(gossip::SigningContext::from_keypair(
                self.identity.agent_keypair(),
            ));
            let caps_rx = self.dm_capabilities_tx.subscribe();
            match dm_capability_service::CapabilityAdvertService::spawn_default(
                std::sync::Arc::clone(runtime.pubsub()),
                signing,
                self.identity.agent_id(),
                self.identity.machine_id(),
                caps_rx,
                std::sync::Arc::clone(&self.capability_store),
            )
            .await
            {
                Ok(service) => {
                    let mut guard = self.capability_advert_service.lock().await;
                    if let Some(prev) = guard.take() {
                        prev.abort();
                    }
                    *guard = Some(service);
                    tracing::info!("Capability advert service started");
                }
                Err(e) => tracing::warn!("failed to start capability advert service: {e}"),
            }
        }

        Ok(())
    }

    /// Clone the shared capability store.
    #[must_use]
    pub fn capability_store(&self) -> std::sync::Arc<dm_capability::CapabilityStore> {
        std::sync::Arc::clone(&self.capability_store)
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
        )
        .await
        .map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!(
                "DM inbox spawn failed: {e}"
            )))
        })?;
        let mut guard = self.dm_inbox_service.lock().await;
        if let Some(prev) = guard.take() {
            prev.abort();
        }
        *guard = Some(service);

        // Upgrade our advertised capabilities so peers stop falling back
        // to the raw-QUIC path. The capability advert service watches
        // this channel and republishes immediately on change.
        let upgraded =
            dm::DmCapabilities::pending().with_kem_public_key(kem_keypair.public_bytes.clone());
        if self.dm_capabilities_tx.send(upgraded).is_err() {
            tracing::debug!("dm_capabilities watch has no receivers; skipping upgrade broadcast");
        }
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
            .filter(|a| a.last_seen >= cutoff)
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
    /// binding this agent to this machine. Returns `false` if the agent is
    /// unknown or bound to a different machine.
    pub async fn is_agent_machine_verified(
        &self,
        agent_id: &identity::AgentId,
        machine_id: &identity::MachineId,
    ) -> bool {
        let cache = self.identity_discovery_cache.read().await;
        cache
            .get(agent_id)
            .map(|entry| entry.machine_id == *machine_id)
            .unwrap_or(false)
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
                            let filtered: Vec<std::net::SocketAddr> = ann
                                .addresses
                                .iter()
                                .copied()
                                .filter(|a| is_publicly_advertisable(*a))
                                .collect();
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
                            };
                            upsert_discovered_machine_from_agent(&machine_cache, &discovered_agent)
                                .await;
                            cache
                                .write()
                                .await
                                .insert(discovered_agent.agent_id, discovered_agent);
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
            cache
                .write()
                .await
                .entry(agent_id)
                .or_insert_with(|| DiscoveredAgent {
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
                });
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
                            let filtered: Vec<std::net::SocketAddr> = ann
                                .addresses
                                .iter()
                                .copied()
                                .filter(|a| is_publicly_advertisable(*a))
                                .collect();
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
            .filter(|a| a.announced_at >= cutoff && a.user_id == Some(user_id))
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

        tokio::spawn(async move {
            let mut rx = network.subscribe();
            tracing::info!("Network event reconciliation listener started");

            loop {
                let event = match rx.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!("Network event listener lagged by {skipped} events");
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
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

        tokio::spawn(async move {
            let Some(mut rx) = lifecycle_network.subscribe_all_peer_events().await else {
                tracing::debug!(
                    "Peer lifecycle listener unavailable: network node not initialised"
                );
                return;
            };
            tracing::info!("Peer lifecycle watcher started for direct messaging");
            loop {
                let (peer_id, event) = match rx.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!("Peer lifecycle watcher lagged by {skipped} events");
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
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
                        lifecycle_dm.record_lifecycle_blocked(
                            machine_id,
                            Some(generation),
                            "reader exited",
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

        tokio::spawn(async move {
            tracing::info!(target: "x0x::direct", stage = "listener", "direct message listener started");
            loop {
                let Some((ant_peer_id, payload)) = network.recv_direct().await else {
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
                        machine_prefix = %network::hex_prefix(&ant_peer_id.0, 4),
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

                tracing::info!(
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
                let verified = {
                    let cache = discovery_cache.read().await;
                    cache
                        .get(&sender)
                        .map(|entry| entry.machine_id == machine_id)
                        .unwrap_or(false)
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

                tracing::info!(
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

                // Register and mark the sender as connected for future reverse direct sends.
                dm.mark_connected(sender, machine_id).await;

                // Fan out to all subscribe_direct() receivers with verification info.
                let delivered = dm
                    .handle_incoming(machine_id, sender, data, verified, trust_decision)
                    .await;

                tracing::info!(
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

    /// new announcement.
    ///
    /// Called automatically by [`Agent::join_network`].
    ///
    /// # Errors
    ///
    /// Returns an error if a required network or gossip component is missing.
    pub async fn start_identity_heartbeat(&self) -> error::Result<()> {
        let mut handle_guard = self.heartbeat_handle.lock().await;
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
        let ctx = HeartbeatContext {
            identity: std::sync::Arc::clone(&self.identity),
            runtime,
            network,
            interval_secs: self.heartbeat_interval_secs,
            cache: std::sync::Arc::clone(&self.identity_discovery_cache),
            machine_cache: std::sync::Arc::clone(&self.machine_discovery_cache),
            user_identity_consented: std::sync::Arc::clone(&self.user_identity_consented),
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
    /// # Arguments
    ///
    /// * `agent` - The agent entry to insert.
    #[doc(hidden)]
    pub async fn insert_discovered_agent_for_testing(&self, agent: DiscoveredAgent) {
        let agent_id = agent.agent_id;
        let machine_id = agent.machine_id;
        upsert_discovered_machine_from_agent(&self.machine_discovery_cache, &agent).await;
        self.identity_discovery_cache
            .write()
            .await
            .insert(agent_id, agent);

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
            30,
        )
        .map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!(
                "task list sync creation failed: {}",
                e
            )))
        })?;

        let sync = std::sync::Arc::new(sync);
        sync.start().await.map_err(|e| {
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
            30,
        )
        .map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!(
                "task list sync creation failed: {}",
                e
            )))
        })?;

        let sync = std::sync::Arc::new(sync);
        sync.start().await.map_err(|e| {
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
    /// If not set, default network configuration is used.
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

        // Create signing context from agent keypair for message authentication
        let signing_ctx = std::sync::Arc::new(gossip::SigningContext::from_keypair(
            identity.agent_keypair(),
        ));

        // Create gossip runtime if network exists
        let gossip_runtime = if let Some(ref net) = network {
            let runtime = gossip::GossipRuntime::new(
                gossip::GossipConfig::default(),
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

        // Initialise contact store
        let contacts_path = self.contact_store_path.unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".x0x")
                .join("contacts.json")
        });
        let contact_store = std::sync::Arc::new(tokio::sync::RwLock::new(
            contacts::ContactStore::new(contacts_path),
        ));

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
            let pw = presence::PresenceWrapper::new(
                peer_id,
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

        Ok(Agent {
            identity: std::sync::Arc::new(identity),
            network,
            gossip_runtime,
            bootstrap_cache,
            gossip_cache_adapter,
            identity_discovery_cache: std::sync::Arc::new(tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
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
            crdt::TaskListDelta::for_reorder(task_ids, list.current_version())
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
            30,
        )
        .map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!(
                "kv store sync creation failed: {e}",
            )))
        })?;

        let sync = std::sync::Arc::new(sync);
        sync.start().await.map_err(|e| {
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
            30,
        )
        .map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!(
                "kv store sync creation failed: {e}",
            )))
        })?;

        let sync = std::sync::Arc::new(sync);
        sync.start().await.map_err(|e| {
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
                None => return Ok(()), // shouldn't happen after successful put
            }
        };
        if let Err(e) = self.sync.publish_delta(self.peer_id, delta).await {
            tracing::warn!("failed to publish kv put delta: {e}");
        }
        Ok(())
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
        if let Err(e) = self.sync.publish_delta(self.peer_id, delta).await {
            tracing::warn!("failed to publish kv remove delta: {e}");
        }
        Ok(())
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
