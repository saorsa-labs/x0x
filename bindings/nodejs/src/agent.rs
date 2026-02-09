use napi::bindgen_prelude::*;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi_derive::napi;
use std::sync::Mutex;

use crate::events::{
    start_connected_forwarding, start_disconnected_forwarding, start_error_forwarding, ErrorEvent,
    EventListener, PeerConnectedEvent, PeerDisconnectedEvent,
};
use crate::identity::{AgentId, MachineId};

/// The core agent that participates in the x0x gossip network.
///
/// Each agent is a peer — there is no client/server distinction.
/// Agents discover each other through gossip and communicate
/// via epidemic broadcast.
#[napi]
pub struct Agent {
    inner: x0x::Agent,
}

#[napi]
impl Agent {
    /// Create a new agent with default configuration.
    ///
    /// This generates a fresh identity with both machine and agent keypairs.
    /// The machine keypair is stored persistently in `~/.x0x/machine.key`.
    #[napi(factory)]
    pub async fn create() -> Result<Self> {
        let inner = x0x::Agent::new().await.map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to create agent: {e}"),
            )
        })?;

        Ok(Agent { inner })
    }

    /// Create an AgentBuilder for fine-grained configuration.
    #[napi(factory)]
    pub fn builder() -> AgentBuilder {
        AgentBuilder {
            inner: Mutex::new(Some(x0x::Agent::builder())),
        }
    }

    /// Get the machine ID for this agent.
    ///
    /// The machine ID is tied to this computer and used for QUIC transport
    /// authentication. It is stored persistently in `~/.x0x/machine.key`.
    #[napi(getter)]
    pub fn machine_id(&self) -> MachineId {
        self.inner.machine_id().into()
    }

    /// Get the agent ID for this agent.
    ///
    /// The agent ID is portable across machines and represents the agent's
    /// persistent identity. It can be exported and imported to run the same
    /// agent on different computers.
    #[napi(getter)]
    pub fn agent_id(&self) -> AgentId {
        self.inner.agent_id().into()
    }

    /// Join the x0x gossip network.
    ///
    /// This begins the gossip protocol, discovering peers and
    /// participating in epidemic broadcast.
    ///
    /// # Example (JavaScript)
    ///
    /// ```javascript
    /// const agent = await Agent.create();
    /// await agent.joinNetwork();
    /// ```
    #[napi]
    pub async fn join_network(&self) -> Result<()> {
        self.inner.join_network().await.map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to join network: {e}"),
            )
        })
    }

    /// Subscribe to messages on a given topic.
    ///
    /// Returns a `Subscription` that yields messages as they arrive
    /// through the gossip network.
    ///
    /// # Example (JavaScript)
    ///
    /// ```javascript
    /// const subscription = await agent.subscribe('coordination');
    /// // Messages will be delivered via callback
    /// ```
    #[napi]
    pub async fn subscribe(&self, topic: String) -> Result<Subscription> {
        let rx =
            self.inner.subscribe(&topic).await.map_err(|e| {
                Error::new(Status::GenericFailure, format!("Failed to subscribe: {e}"))
            })?;

        Ok(Subscription { _inner: rx })
    }

    /// Publish a message to a topic.
    ///
    /// The message will propagate through the gossip network via
    /// epidemic broadcast — every agent that receives it will
    /// relay it to its neighbours.
    ///
    /// # Example (JavaScript)
    ///
    /// ```javascript
    /// await agent.publish('coordination', Buffer.from('hello'));
    /// ```
    #[napi]
    pub async fn publish(&self, topic: String, payload: Buffer) -> Result<()> {
        self.inner
            .publish(&topic, payload.to_vec())
            .await
            .map_err(|e| Error::new(Status::GenericFailure, format!("Failed to publish: {e}")))
    }

    /// Register an event listener for peer connected events.
    ///
    /// This follows the EventEmitter pattern with event-specific handlers.
    ///
    /// # Example (JavaScript)
    ///
    /// ```javascript
    /// const listener = agent.onConnected((event) => {
    ///   console.log('Peer connected:', event.peer_id, event.address);
    /// });
    ///
    /// // Later, stop listening:
    /// await listener.stop();
    /// ```
    ///
    /// # Arguments
    ///
    /// * `callback` - Function that receives `PeerConnectedEvent` objects
    ///
    /// # Returns
    ///
    /// An `EventListener` handle that can be used to stop listening via `listener.stop()`
    #[napi]
    pub fn on_connected(
        &self,
        callback: ThreadsafeFunction<PeerConnectedEvent, ErrorStrategy::CalleeHandled>,
    ) -> Result<EventListener> {
        let network = self.inner.network().ok_or_else(|| {
            Error::new(
                Status::GenericFailure,
                "Network not initialized - call joinNetwork() first",
            )
        })?;

        Ok(start_connected_forwarding(network, callback))
    }

    /// Register an event listener for peer disconnected events.
    ///
    /// # Example (JavaScript)
    ///
    /// ```javascript
    /// const listener = agent.onDisconnected((event) => {
    ///   console.log('Peer disconnected:', event.peer_id);
    /// });
    /// ```
    #[napi]
    pub fn on_disconnected(
        &self,
        callback: ThreadsafeFunction<PeerDisconnectedEvent, ErrorStrategy::CalleeHandled>,
    ) -> Result<EventListener> {
        let network = self.inner.network().ok_or_else(|| {
            Error::new(
                Status::GenericFailure,
                "Network not initialized - call joinNetwork() first",
            )
        })?;

        Ok(start_disconnected_forwarding(network, callback))
    }

    /// Register an event listener for connection error events.
    ///
    /// # Example (JavaScript)
    ///
    /// ```javascript
    /// const listener = agent.onError((event) => {
    ///   console.error('Connection error:', event.message);
    ///   if (event.peer_id) {
    ///     console.error('  Peer:', event.peer_id);
    ///   }
    /// });
    /// ```
    #[napi]
    pub fn on_error(
        &self,
        callback: ThreadsafeFunction<ErrorEvent, ErrorStrategy::CalleeHandled>,
    ) -> Result<EventListener> {
        let network = self.inner.network().ok_or_else(|| {
            Error::new(
                Status::GenericFailure,
                "Network not initialized - call joinNetwork() first",
            )
        })?;

        Ok(start_error_forwarding(network, callback))
    }

    /// Create a new collaborative task list.
    ///
    /// This creates a task list that will be synchronized across all agents
    /// subscribed to the given topic via gossip.
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable name for the task list
    /// * `topic` - Gossip topic for synchronization
    ///
    /// # Returns
    ///
    /// Promise resolving to a TaskList handle
    ///
    /// # Example (JavaScript)
    ///
    /// ```javascript
    /// const taskList = await agent.createTaskList(
    ///   "Sprint 42 Tasks",
    ///   "team/sprint42"
    /// );
    /// ```
    #[napi]
    pub async fn create_task_list(
        &self,
        name: String,
        topic: String,
    ) -> Result<crate::task_list::TaskList> {
        let handle = self
            .inner
            .create_task_list(&name, &topic)
            .await
            .map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Failed to create task list: {e}"),
                )
            })?;

        Ok(crate::task_list::TaskList::from_handle(handle))
    }

    /// Join an existing collaborative task list.
    ///
    /// Subscribe to an existing task list by its gossip topic. The agent
    /// will sync all tasks and updates via epidemic broadcast.
    ///
    /// # Arguments
    ///
    /// * `topic` - Gossip topic of the task list to join
    ///
    /// # Returns
    ///
    /// Promise resolving to a TaskList handle
    ///
    /// # Example (JavaScript)
    ///
    /// ```javascript
    /// const taskList = await agent.joinTaskList("team/sprint42");
    /// const tasks = await taskList.listTasks();
    /// console.log(`Joined list with ${tasks.length} tasks`);
    /// ```
    #[napi]
    pub async fn join_task_list(&self, topic: String) -> Result<crate::task_list::TaskList> {
        let handle = self.inner.join_task_list(&topic).await.map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to join task list: {e}"),
            )
        })?;

        Ok(crate::task_list::TaskList::from_handle(handle))
    }
}

/// Builder for configuring an Agent before connecting to the network.
///
/// The builder allows customization of the agent's identity:
/// - Machine key path: Where to store/load the machine keypair
/// - Agent keypair: Import a portable agent identity from another machine
///
/// ## Lifecycle
///
/// The builder is consumed by the `build()` method whether it succeeds or fails.
/// After calling `build()`, you must create a new builder to configure another agent.
///
/// This design follows Rust's ownership model where `build()` consumes the builder.
#[napi]
pub struct AgentBuilder {
    inner: Mutex<Option<x0x::AgentBuilder>>,
}

#[napi]
impl AgentBuilder {
    /// Set the path where the machine keypair should be stored/loaded.
    ///
    /// Default: `~/.x0x/machine.key`
    #[napi]
    pub fn with_machine_key(&self, path: String) -> Result<&Self> {
        let mut guard = self.inner.lock().unwrap();
        let builder = guard.take().ok_or_else(|| {
            Error::new(
                Status::GenericFailure,
                "Builder already consumed by build()",
            )
        })?;

        *guard = Some(builder.with_machine_key(path));
        Ok(self)
    }

    /// Import an agent keypair from bytes.
    ///
    /// This allows running the same agent identity on different machines.
    ///
    /// # Arguments
    ///
    /// * `public_key_bytes` - The ML-DSA-65 public key (2592 bytes)
    /// * `secret_key_bytes` - The ML-DSA-65 secret key (4032 bytes)
    #[napi]
    pub fn with_agent_key(
        &self,
        public_key_bytes: Vec<u8>,
        secret_key_bytes: Vec<u8>,
    ) -> Result<&Self> {
        let mut guard = self.inner.lock().unwrap();
        let builder = guard.take().ok_or_else(|| {
            Error::new(
                Status::GenericFailure,
                "Builder already consumed by build()",
            )
        })?;

        let keypair = x0x::identity::AgentKeypair::from_bytes(&public_key_bytes, &secret_key_bytes)
            .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid agent keypair: {e}")))?;

        *guard = Some(builder.with_agent_key(keypair));
        Ok(self)
    }

    /// Build the agent with the configured settings.
    ///
    /// **IMPORTANT**: This method consumes the builder whether it succeeds or fails.
    /// If you need to retry after a failure, create a new builder with `Agent.builder()`.
    ///
    /// This design follows Rust's ownership semantics where the underlying builder
    /// is consumed by the build operation.
    #[napi]
    pub async fn build(&self) -> Result<Agent> {
        // Extract builder from mutex before await (MutexGuard is not Send)
        let builder = {
            let mut guard = self.inner.lock().unwrap();
            guard.take().ok_or_else(|| {
                Error::new(
                    Status::GenericFailure,
                    "Builder already consumed - create a new builder with Agent.builder()",
                )
            })?
        }; // guard dropped here

        // Now we can await without holding the guard
        let inner = builder.build().await.map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to build agent: {e}"),
            )
        })?;

        Ok(Agent { inner })
    }
}

/// A message received from the gossip network.
#[napi(object)]
pub struct Message {
    /// The originating agent's identifier.
    pub origin: String,
    /// The message payload.
    pub payload: Buffer,
    /// The topic this message was published to.
    pub topic: String,
}

/// A subscription to messages on a topic.
///
/// Call `unsubscribe()` to stop receiving messages.
#[napi]
pub struct Subscription {
    _inner: x0x::Subscription,
}

#[napi]
impl Subscription {
    /// Unsubscribe from the topic.
    ///
    /// After calling this, no more messages will be delivered.
    #[napi]
    pub fn unsubscribe(&mut self) {
        // The Subscription will be dropped, closing the channel
    }
}
