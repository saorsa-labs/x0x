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
//! - Nuremberg, DE · Singapore, SG · Tokyo, JP
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

/// Gossip overlay networking for x0x.
pub mod gossip;

/// CRDT-based collaborative task lists.
pub mod crdt;

/// MLS (Messaging Layer Security) group encryption.
pub mod mls;

// Re-export key gossip types (including new pubsub components)
pub use gossip::{
    GossipConfig, GossipRuntime, PubSubManager, PubSubMessage, SigningContext, Subscription,
};

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
#[derive(Debug)]
pub struct Agent {
    identity: std::sync::Arc<identity::Identity>,
    /// The network node for P2P communication.
    #[allow(dead_code)]
    network: Option<std::sync::Arc<network::NetworkNode>>,
    /// The gossip runtime for pub/sub messaging.
    gossip_runtime: Option<std::sync::Arc<gossip::GossipRuntime>>,
    /// Cache of discovered agents from identity announcements.
    identity_discovery_cache: std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<identity::AgentId, DiscoveredAgent>>,
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
pub const IDENTITY_ANNOUNCE_TOPIC: &str = "x0x.identity.announce.v1";

/// Return the shard-specific gossip topic for the given `agent_id`.
///
/// Each agent publishes identity announcements to a deterministic shard topic
/// (`x0x.identity.shard.<u16>`) derived from its agent ID, in addition to the
/// legacy broadcast topic.  This distributes announcements across 65,536 shards
/// so that at scale not every node is forced to receive every announcement.
///
/// The shard is computed with `saorsa_gossip_rendezvous::calculate_shard`, which
/// applies BLAKE3(`"saorsa-rendezvous" || agent_id`) and takes the low 16 bits.
#[must_use]
pub fn shard_topic_for_agent(agent_id: &identity::AgentId) -> String {
    let shard = saorsa_gossip_rendezvous::calculate_shard(&agent_id.0);
    format!("x0x.identity.shard.{shard}")
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

/// Default interval between identity heartbeat re-announcements (seconds).
pub const IDENTITY_HEARTBEAT_INTERVAL_SECS: u64 = 300;

/// Default TTL for discovered agent cache entries (seconds).
///
/// Entries not refreshed within this window are filtered from
/// [`Agent::presence`] and [`Agent::discovered_agents`].
pub const IDENTITY_TTL_SECS: u64 = 900;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IdentityAnnouncementUnsigned {
    agent_id: identity::AgentId,
    machine_id: identity::MachineId,
    user_id: Option<identity::UserId>,
    agent_certificate: Option<identity::AgentCertificate>,
    machine_public_key: Vec<u8>,
    addresses: Vec<std::net::SocketAddr>,
    announced_at: u64,
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
    user_keypair: Option<identity::UserKeypair>,
    user_key_path: Option<std::path::PathBuf>,
    #[allow(dead_code)]
    network_config: Option<network::NetworkConfig>,
    heartbeat_interval_secs: Option<u64>,
    identity_ttl_secs: Option<u64>,
}

/// Context captured by the background identity heartbeat task.
struct HeartbeatContext {
    identity: std::sync::Arc<identity::Identity>,
    runtime: std::sync::Arc<gossip::GossipRuntime>,
    #[allow(dead_code)]
    network: std::sync::Arc<network::NetworkNode>,
    interval_secs: u64,
    cache: std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<identity::AgentId, DiscoveredAgent>>,
    >,
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
        let unsigned = IdentityAnnouncementUnsigned {
            agent_id: self.identity.agent_id(),
            machine_id: self.identity.machine_id(),
            user_id: self
                .identity
                .user_keypair()
                .map(identity::UserKeypair::user_id),
            agent_certificate: self.identity.agent_certificate().cloned(),
            machine_public_key: machine_public_key.clone(),
            addresses: Vec::new(),
            announced_at,
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
        };
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
        self.cache.write().await.insert(
            announcement.agent_id,
            DiscoveredAgent {
                agent_id: announcement.agent_id,
                machine_id: announcement.machine_id,
                user_id: announcement.user_id,
                addresses: announcement.addresses,
                announced_at: announcement.announced_at,
                last_seen: now,
                machine_public_key: machine_public_key.clone(),
            },
        );
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
            user_keypair: None,
            user_key_path: None,
            network_config: None,
            heartbeat_interval_secs: None,
            identity_ttl_secs: None,
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
        let announcement =
            self.build_identity_announcement(include_user_identity, human_consent)?;
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
        self.identity_discovery_cache.write().await.insert(
            announcement.agent_id,
            DiscoveredAgent {
                agent_id: announcement.agent_id,
                machine_id: announcement.machine_id,
                user_id: announcement.user_id,
                addresses: announcement.addresses.clone(),
                announced_at: announcement.announced_at,
                last_seen: now,
                machine_public_key: announcement.machine_public_key.clone(),
            },
        );

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
            .filter(|a| a.announced_at >= cutoff)
            .cloned()
            .collect();
        agents.sort_by(|a, b| a.agent_id.0.cmp(&b.agent_id.0));
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
        agents.sort_by(|a, b| a.agent_id.0.cmp(&b.agent_id.0));
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
        let cache = std::sync::Arc::clone(&self.identity_discovery_cache);

        tokio::spawn(async move {
            loop {
                // Drain whichever subscription fires next; deduplicate by AgentId in cache.
                let msg = tokio::select! {
                    Some(m) = sub_legacy.recv() => m,
                    Some(m) = sub_shard.recv() => m,
                    else => break,
                };
                let announcement = match bincode::deserialize::<IdentityAnnouncement>(&msg.payload)
                {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::debug!("Ignoring invalid identity announcement payload: {}", e);
                        continue;
                    }
                };

                if let Err(e) = announcement.verify() {
                    tracing::warn!("Ignoring unverifiable identity announcement: {}", e);
                    continue;
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());

                cache.write().await.insert(
                    announcement.agent_id,
                    DiscoveredAgent {
                        agent_id: announcement.agent_id,
                        machine_id: announcement.machine_id,
                        user_id: announcement.user_id,
                        addresses: announcement.addresses.clone(),
                        announced_at: announcement.announced_at,
                        last_seen: now,
                        machine_public_key: announcement.machine_public_key.clone(),
                    },
                );
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
            Some(addr) if addr.port() > 0 => vec![addr],
            _ => Vec::new(),
        }
    }

    fn build_identity_announcement(
        &self,
        include_user_identity: bool,
        human_consent: bool,
    ) -> error::Result<IdentityAnnouncement> {
        if include_user_identity && !human_consent {
            return Err(error::IdentityError::Storage(std::io::Error::other(
                "human identity disclosure requires explicit human consent",
            )));
        }

        let (user_id, agent_certificate) = if include_user_identity {
            let user_id = self.user_id().ok_or_else(|| {
                error::IdentityError::Storage(std::io::Error::other(
                    "human identity disclosure requested but no user identity is configured",
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
            addresses: self.announcement_addresses(),
            announced_at: Self::unix_timestamp_secs(),
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

        let bootstrap_nodes = network.config().bootstrap_nodes.clone();
        if bootstrap_nodes.is_empty() {
            tracing::debug!("No bootstrap peers configured");
            if let Err(e) = self.announce_identity(false, false).await {
                tracing::warn!("Initial identity announcement failed: {}", e);
            }
            if let Err(e) = self.start_identity_heartbeat().await {
                tracing::warn!("Failed to start identity heartbeat: {e}");
            }
            return Ok(());
        }

        // Round 1: Connect to all bootstrap peers in parallel
        let mut failed = self.connect_peers_parallel(network, &bootstrap_nodes).await;
        let connected = bootstrap_nodes.len() - failed.len();
        tracing::info!(
            "Bootstrap round 1: {}/{} peers connected",
            connected,
            bootstrap_nodes.len()
        );

        // Retry rounds for failed peers
        for round in 2..=3 {
            if failed.is_empty() {
                break;
            }
            // Wait for stale connections on remote nodes to expire
            let delay = std::time::Duration::from_secs(if round == 2 { 10 } else { 15 });
            tracing::info!(
                "Retrying {} failed peers in {}s (round {})",
                failed.len(),
                delay.as_secs(),
                round
            );
            tokio::time::sleep(delay).await;

            failed = self.connect_peers_parallel(network, &failed).await;
            let total_connected = bootstrap_nodes.len() - failed.len();
            tracing::info!(
                "Bootstrap round {}: {}/{} peers connected",
                round,
                total_connected,
                bootstrap_nodes.len()
            );
        }

        if !failed.is_empty() {
            tracing::warn!(
                "Could not connect to {} bootstrap peers: {:?}",
                failed.len(),
                failed
            );
        }

        tracing::info!(
            "Network join complete. Connected to {}/{} bootstrap peers.",
            bootstrap_nodes.len() - failed.len(),
            bootstrap_nodes.len()
        );

        // Join the HyParView membership overlay via bootstrap nodes.
        // This triggers JOIN messages that propagate through the network,
        // allowing other agents to discover this node and establish
        // overlay connections for gossip dissemination.
        if let Some(ref runtime) = self.gossip_runtime {
            let seeds: Vec<String> = bootstrap_nodes
                .iter()
                .filter(|addr| !failed.contains(addr))
                .map(|addr| addr.to_string())
                .collect();
            if !seeds.is_empty() {
                if let Err(e) = runtime.membership().join(seeds).await {
                    tracing::warn!("HyParView membership join failed: {e}");
                }
            }
        }

        if let Err(e) = self.announce_identity(false, false).await {
            tracing::warn!("Initial identity announcement failed: {}", e);
        }
        if let Err(e) = self.start_identity_heartbeat().await {
            tracing::warn!("Failed to start identity heartbeat: {e}");
        }

        Ok(())
    }

    /// Connect to multiple peers in parallel, returning the list of failed addresses.
    async fn connect_peers_parallel(
        &self,
        network: &std::sync::Arc<network::NetworkNode>,
        addrs: &[std::net::SocketAddr],
    ) -> Vec<std::net::SocketAddr> {
        let handles: Vec<_> = addrs
            .iter()
            .map(|addr| {
                let net = network.clone();
                let addr = *addr;
                tokio::spawn(async move {
                    tracing::debug!("Connecting to bootstrap peer: {}", addr);
                    match net.connect_addr(addr).await {
                        Ok(_) => {
                            tracing::info!("Connected to bootstrap peer: {}", addr);
                            None
                        }
                        Err(e) => {
                            tracing::warn!("Failed to connect to {}: {}", addr, e);
                            Some(addr)
                        }
                    }
                })
            })
            .collect();

        let mut failed = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Some(addr)) => failed.push(addr),
                Ok(None) => {}
                Err(e) => tracing::error!("Connection task panicked: {}", e),
            }
        }
        failed
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
            .filter(|a| a.announced_at >= cutoff)
            .map(|a| a.agent_id)
            .collect();
        agents.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(agents)
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
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);

        loop {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let timeout = tokio::time::sleep_until(deadline);
            tokio::select! {
                Some(msg) = sub.recv() => {
                    if let Ok(ann) = bincode::deserialize::<IdentityAnnouncement>(&msg.payload) {
                        if ann.verify().is_ok() && ann.agent_id == agent_id {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map_or(0, |d| d.as_secs());
                            let addrs = ann.addresses.clone();
                            cache.write().await.insert(
                                ann.agent_id,
                                DiscoveredAgent {
                                    agent_id: ann.agent_id,
                                    machine_id: ann.machine_id,
                                    user_id: ann.user_id,
                                    addresses: ann.addresses,
                                    announced_at: ann.announced_at,
                                    last_seen: now,
                                    machine_public_key: ann.machine_public_key.clone(),
                                },
                            );
                            return Ok(Some(addrs));
                        }
                    }
                }
                _ = timeout => break,
            }
        }

        // Stage 3: rendezvous shard subscription — wait up to 5 s.
        if let Some(addrs) = self.find_agent_rendezvous(agent_id, 5).await? {
            return Ok(Some(addrs));
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
    #[must_use]
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.network.as_ref().and_then(|n| n.local_addr())
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

    /// Start the background identity heartbeat task.
    ///
    /// Idempotent — if the heartbeat is already running, returns `Ok(())` immediately.
    /// The heartbeat re-announces this agent's identity at `heartbeat_interval_secs`
    /// intervals so that late-joining peers can discover it without waiting for a
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
                        .and_then(|b| bincode::deserialize(b).ok())
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
        self.identity_discovery_cache
            .write()
            .await
            .insert(agent.agent_id, agent);
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

        // Build identity with optional user layer
        let identity = if let Some(user_kp) = user_keypair {
            // Try to load existing certificate, or issue a new one
            // IMPORTANT: Verify the cert matches the current user key
            let cert = if storage::agent_certificate_exists().await {
                match storage::load_agent_certificate().await {
                    Ok(c) => {
                        // Verify cert is for the current user - if not, re-issue
                        let cert_matches_user = c
                            .user_id()
                            .map(|uid| uid == user_kp.user_id())
                            .unwrap_or(false);
                        if cert_matches_user {
                            c
                        } else {
                            // Cert was for a different user, issue new one
                            let new_cert =
                                identity::AgentCertificate::issue(&user_kp, &agent_keypair)?;
                            storage::save_agent_certificate(&new_cert).await?;
                            new_cert
                        }
                    }
                    Err(_) => {
                        let c = identity::AgentCertificate::issue(&user_kp, &agent_keypair)?;
                        storage::save_agent_certificate(&c).await?;
                        c
                    }
                }
            } else {
                let c = identity::AgentCertificate::issue(&user_kp, &agent_keypair)?;
                storage::save_agent_certificate(&c).await?;
                c
            };
            identity::Identity::new_with_user(machine_keypair, agent_keypair, user_kp, cert)
        } else {
            identity::Identity::new(machine_keypair, agent_keypair)
        };

        // Create network node if configured
        let network = if let Some(config) = self.network_config {
            let node = network::NetworkNode::new(config).await.map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "network initialization failed: {}",
                    e
                )))
            })?;
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

        Ok(Agent {
            identity: std::sync::Arc::new(identity),
            network,
            gossip_runtime,
            identity_discovery_cache: std::sync::Arc::new(tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            identity_listener_started: std::sync::atomic::AtomicBool::new(false),
            heartbeat_interval_secs: self
                .heartbeat_interval_secs
                .unwrap_or(IDENTITY_HEARTBEAT_INTERVAL_SECS),
            identity_ttl_secs: self.identity_ttl_secs.unwrap_or(IDENTITY_TTL_SECS),
            heartbeat_handle: tokio::sync::Mutex::new(None),
            rendezvous_advertised: std::sync::atomic::AtomicBool::new(false),
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
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let task_id = crdt::TaskId::new(&title, &self.agent_id, timestamp);
        let metadata = crdt::TaskMetadata::new(title, description, 128, self.agent_id, timestamp);
        let task = crdt::TaskItem::new(task_id, metadata, self.peer_id);

        let mut list = self.sync.write().await;
        list.add_task(task, self.peer_id, timestamp).map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!("add_task failed: {}", e)))
        })?;

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
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut list = self.sync.write().await;
        list.claim_task(&task_id, self.agent_id, self.peer_id, timestamp)
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "claim_task failed: {}",
                    e
                )))
            })
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
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut list = self.sync.write().await;
        list.complete_task(&task_id, self.agent_id, self.peer_id, timestamp)
            .map_err(|e| {
                error::IdentityError::Storage(std::io::Error::other(format!(
                    "complete_task failed: {}",
                    e
                )))
            })
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
        let mut list = self.sync.write().await;
        list.reorder(task_ids, self.peer_id).map_err(|e| {
            error::IdentityError::Storage(std::io::Error::other(format!("reorder failed: {}", e)))
        })
    }
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
}
