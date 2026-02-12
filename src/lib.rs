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

/// Gossip overlay networking for x0x.
pub mod gossip;

/// CRDT-based collaborative task lists.
pub mod crdt;

/// MLS (Messaging Layer Security) group encryption.
pub mod mls;

// Re-export key gossip types (including new pubsub components)
pub use gossip::{GossipConfig, GossipRuntime, PubSubManager, PubSubMessage, Subscription};

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
    identity: identity::Identity,
    /// The network node for P2P communication.
    #[allow(dead_code)]
    network: Option<std::sync::Arc<network::NetworkNode>>,
    /// The gossip runtime for pub/sub messaging.
    gossip_runtime: Option<std::sync::Arc<gossip::GossipRuntime>>,
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

        let bootstrap_nodes = network.config().bootstrap_nodes.clone();
        if bootstrap_nodes.is_empty() {
            tracing::debug!("No bootstrap peers configured");
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
    /// # Example
    ///
    /// ```ignore
    /// let list = agent.create_task_list("Sprint Planning", "team-sprint").await?;
    /// ```
    pub async fn create_task_list(
        &self,
        _name: &str,
        _topic: &str,
    ) -> error::Result<TaskListHandle> {
        // TODO: Implement task list creation when gossip runtime is available
        // This would:
        // 1. Create a new TaskList with TaskListId::from_content(name, agent_id, timestamp)
        // 2. Wrap it in TaskListSync with the gossip runtime
        // 3. Return a TaskListHandle
        Err(error::IdentityError::Storage(std::io::Error::other(
            "TaskList creation not yet implemented",
        )))
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
    /// # Example
    ///
    /// ```ignore
    /// let list = agent.join_task_list("team-sprint").await?;
    /// ```
    pub async fn join_task_list(&self, _topic: &str) -> error::Result<TaskListHandle> {
        // TODO: Implement task list joining when gossip runtime is available
        // This would:
        // 1. Create an empty TaskList (or load from persistence if exists)
        // 2. Subscribe to the topic to receive updates
        // 3. Start anti-entropy sync
        // 4. Return a TaskListHandle
        Err(error::IdentityError::Storage(std::io::Error::other(
            "TaskList joining not yet implemented",
        )))
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
                        let cert_matches_user = c.user_id()
                            .map(|uid| uid == user_kp.user_id())
                            .unwrap_or(false);
                        if cert_matches_user {
                            c
                        } else {
                            // Cert was for a different user, issue new one
                            let new_cert = identity::AgentCertificate::issue(&user_kp, &agent_keypair)?;
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

        // Create gossip runtime if network exists
        let gossip_runtime = network.as_ref().map(|net| {
            let net_arc = std::sync::Arc::clone(net);
            std::sync::Arc::new(gossip::GossipRuntime::new(
                gossip::GossipConfig::default(),
                net_arc,
            ))
        });

        Ok(Agent {
            identity,
            network,
            gossip_runtime,
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
#[derive(Debug, Clone)]
pub struct TaskListHandle {
    _sync: std::sync::Arc<()>, // Placeholder for Arc<TaskListSync>
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
    pub async fn add_task(
        &self,
        _title: String,
        _description: String,
    ) -> error::Result<crdt::TaskId> {
        // TODO: Implement when TaskListSync is available
        Err(error::IdentityError::Storage(std::io::Error::other(
            "TaskListHandle not yet implemented",
        )))
    }

    /// Claim a task in the list.
    ///
    /// # Arguments
    ///
    /// * `task_id` - ID of the task to claim
    pub async fn claim_task(&self, _task_id: crdt::TaskId) -> error::Result<()> {
        // TODO: Implement when TaskListSync is available
        Err(error::IdentityError::Storage(std::io::Error::other(
            "TaskListHandle not yet implemented",
        )))
    }

    /// Complete a task in the list.
    ///
    /// # Arguments
    ///
    /// * `task_id` - ID of the task to complete
    pub async fn complete_task(&self, _task_id: crdt::TaskId) -> error::Result<()> {
        // TODO: Implement when TaskListSync is available
        Err(error::IdentityError::Storage(std::io::Error::other(
            "TaskListHandle not yet implemented",
        )))
    }

    /// List all tasks in their current order.
    ///
    /// # Returns
    ///
    /// A vector of `TaskSnapshot` representing the current state.
    pub async fn list_tasks(&self) -> error::Result<Vec<TaskSnapshot>> {
        // TODO: Implement when TaskListSync is available
        Err(error::IdentityError::Storage(std::io::Error::other(
            "TaskListHandle not yet implemented",
        )))
    }

    /// Reorder tasks in the list.
    ///
    /// # Arguments
    ///
    /// * `task_ids` - New ordering of task IDs
    pub async fn reorder(&self, _task_ids: Vec<crdt::TaskId>) -> error::Result<()> {
        // TODO: Implement when TaskListSync is available
        Err(error::IdentityError::Storage(std::io::Error::other(
            "TaskListHandle not yet implemented",
        )))
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
}
