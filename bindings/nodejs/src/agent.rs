use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::sync::Mutex;

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
                format!("Failed to create agent: {}", e),
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
            .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid agent keypair: {}", e)))?;

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
                format!("Failed to build agent: {}", e),
            )
        })?;

        Ok(Agent { inner })
    }
}
