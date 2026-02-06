use napi::bindgen_prelude::*;
use napi_derive::napi;

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
    ///
    /// # TypeScript
    /// ```typescript
    /// const agent = await Agent.create();
    /// console.log(agent.agentId.toString());
    /// ```
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
    ///
    /// # TypeScript
    /// ```typescript
    /// const agent = await Agent.builder()
    ///     .withMachineKey("/custom/path/machine.key")
    ///     .build();
    /// ```
    #[napi(factory)]
    pub fn builder() -> AgentBuilder {
        AgentBuilder {
            inner: x0x::Agent::builder(),
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
/// **Important**: The builder is consumed when you call `build()`. You cannot
/// reuse the same builder instance for multiple agents.
#[napi]
pub struct AgentBuilder {
    inner: x0x::AgentBuilder,
}

#[napi]
impl AgentBuilder {
    /// Set the path where the machine keypair should be stored/loaded.
    ///
    /// Default: `~/.x0x/machine.key`
    ///
    /// # TypeScript
    /// ```typescript
    /// const agent = await Agent.builder()
    ///     .withMachineKey("/custom/path/machine.key")
    ///     .build();
    /// ```
    #[napi]
    pub fn with_machine_key(mut self, path: String) -> Self {
        self.inner = self.inner.with_machine_key(path);
        self
    }

    /// Import an agent keypair from bytes.
    ///
    /// This allows running the same agent identity on different machines.
    ///
    /// # Arguments
    ///
    /// * `public_key_bytes` - The ML-DSA-65 public key (2592 bytes)
    /// * `secret_key_bytes` - The ML-DSA-65 secret key (4032 bytes)
    ///
    /// # TypeScript
    /// ```typescript
    /// const publicKey = Buffer.from(/* 2592 bytes */);
    /// const secretKey = Buffer.from(/* 4032 bytes */);
    /// 
    /// const agent = await Agent.builder()
    ///     .withAgentKey(publicKey, secretKey)
    ///     .build();
    /// ```
    #[napi]
    pub fn with_agent_key(
        mut self,
        public_key_bytes: Vec<u8>,
        secret_key_bytes: Vec<u8>,
    ) -> Result<Self> {
        let keypair = x0x::identity::AgentKeypair::from_bytes(&public_key_bytes, &secret_key_bytes)
            .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid agent keypair: {}", e)))?;

        self.inner = self.inner.with_agent_key(keypair);
        Ok(self)
    }

    /// Build the agent with the configured settings.
    ///
    /// **Note**: This method consumes the builder. You cannot reuse the builder
    /// after calling build(). If you need multiple agents with the same configuration,
    /// create a new builder for each agent.
    ///
    /// # TypeScript
    /// ```typescript
    /// const builder = Agent.builder().withMachineKey("/custom/path");
    /// const agent = await builder.build(); // builder is now consumed
    /// // builder.build() would fail - builder has been moved
    /// ```
    #[napi]
    pub async fn build(self) -> Result<Agent> {
        let inner = self.inner.build().await.map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to build agent: {}", e),
            )
        })?;

        Ok(Agent { inner })
    }
}
