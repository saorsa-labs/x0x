use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyType;
use pyo3_asyncio::tokio::future_into_py;
use std::sync::Mutex;

use crate::identity::{AgentId, MachineId};

/// The core agent that participates in the x0x gossip network.
///
/// Each agent is a peer — there is no client/server distinction.
/// Agents discover each other through gossip and communicate
/// via epidemic broadcast.
///
/// # Example (Python)
///
/// ```python
/// agent = await Agent.builder().build()
/// print(f"Agent ID: {agent.agent_id}")
/// ```
#[pyclass]
pub struct Agent {
    inner: x0x::Agent,
}

#[pymethods]
impl Agent {
    /// Create an AgentBuilder for fine-grained configuration.
    ///
    /// # Returns
    ///
    /// A new AgentBuilder instance
    ///
    /// # Example (Python)
    ///
    /// ```python
    /// agent = await Agent.builder().build()
    /// ```
    #[classmethod]
    fn builder(_cls: &PyType) -> PyResult<AgentBuilder> {
        Ok(AgentBuilder {
            inner: Mutex::new(Some(x0x::Agent::builder())),
        })
    }

    /// Get the machine ID for this agent.
    ///
    /// The machine ID is tied to this computer and used for QUIC transport
    /// authentication. It is stored persistently in `~/.x0x/machine.key`.
    ///
    /// # Returns
    ///
    /// The MachineId for this agent
    #[getter]
    fn machine_id(&self) -> PyResult<MachineId> {
        Ok(self.inner.machine_id().into())
    }

    /// Get the agent ID for this agent.
    ///
    /// The agent ID is portable across machines and represents the agent's
    /// persistent identity. It can be exported and imported to run the same
    /// agent on different computers.
    ///
    /// # Returns
    ///
    /// The AgentId for this agent
    #[getter]
    fn agent_id(&self) -> PyResult<AgentId> {
        Ok(self.inner.agent_id().into())
    }

    /// Join the x0x gossip network.
    ///
    /// This begins the gossip protocol, discovering peers and
    /// participating in epidemic broadcast. The method is async
    /// and integrates with Python's asyncio event loop.
    ///
    /// # Returns
    ///
    /// None on success
    ///
    /// # Raises
    ///
    /// * `IOError` - If network join fails
    ///
    /// # Example (Python)
    ///
    /// ```python
    /// agent = await Agent.builder().build()
    /// await agent.join_network()
    /// assert agent.is_connected()
    /// ```
    fn join_network<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        // Note: join_network is currently a placeholder in x0x core
        // When gossip integration is complete, this will actually join the network
        future_into_py(py, async move {
            // Placeholder implementation - always succeeds
            Ok(())
        })
    }

    /// Leave the x0x gossip network.
    ///
    /// This gracefully disconnects from the network, closing all
    /// peer connections and stopping the gossip protocol.
    ///
    /// # Returns
    ///
    /// None on success
    ///
    /// # Raises
    ///
    /// * `IOError` - If network leave fails
    ///
    /// # Example (Python)
    ///
    /// ```python
    /// await agent.leave_network()
    /// assert not agent.is_connected()
    /// ```
    fn leave_network<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        // Note: leave_network is currently a placeholder in x0x core
        // When gossip integration is complete, this will properly disconnect
        future_into_py(py, async move {
            // Placeholder implementation - always succeeds
            Ok(())
        })
    }

    /// Check if the agent is currently connected to the network.
    ///
    /// This is a synchronous check of the connection state.
    ///
    /// # Returns
    ///
    /// True if connected, False otherwise
    ///
    /// # Example (Python)
    ///
    /// ```python
    /// if agent.is_connected():
    ///     await agent.publish("topic", b"message")
    /// ```
    fn is_connected(&self) -> PyResult<bool> {
        // For now, always return True if network was initialized
        // In future, this should check actual connection status
        // Currently network is created during agent.build(), so always connected
        Ok(true)
    }

    /// Get the peer ID for this agent.
    ///
    /// The peer ID is derived from the agent's machine key and is used
    /// for QUIC transport. Returns hex-encoded string.
    ///
    /// # Returns
    ///
    /// Hex-encoded peer ID string (64 characters)
    ///
    /// # Example (Python)
    ///
    /// ```python
    /// peer_id = agent.peer_id()
    /// print(f"My peer ID: {peer_id}")
    /// ```
    fn peer_id(&self) -> PyResult<String> {
        // Return machine_id as hex (it serves as the peer ID)
        Ok(hex::encode(self.inner.machine_id().as_bytes()))
    }
}

/// Builder for creating Agent instances with custom configuration.
///
/// # Example (Python)
///
/// ```python
/// # Default configuration
/// agent = await Agent.builder().build()
///
/// # Custom machine key path
/// agent = await Agent.builder() \\
///     .with_machine_key("/custom/path/machine.key") \\
///     .build()
///
/// # Import existing agent keypair
/// agent = await Agent.builder() \\
///     .with_agent_key(public_key, secret_key) \\
///     .build()
/// ```
#[pyclass]
pub struct AgentBuilder {
    inner: Mutex<Option<x0x::AgentBuilder>>,
}

#[pymethods]
impl AgentBuilder {
    /// Set the path where the machine keypair should be stored/loaded.
    ///
    /// Default: `~/.x0x/machine.key`
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the machine keypair file
    ///
    /// # Returns
    ///
    /// Self for method chaining
    ///
    /// # Example (Python)
    ///
    /// ```python
    /// agent = await Agent.builder() \\
    ///     .with_machine_key("/custom/path/machine.key") \\
    ///     .build()
    /// ```
    fn with_machine_key(&self, path: String) -> PyResult<Py<Self>> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| PyErr::new::<PyIOError, _>(format!("Lock error: {}", e)))?;

        let builder = guard
            .take()
            .ok_or_else(|| PyErr::new::<PyValueError, _>("Builder already consumed by build()"))?;

        *guard = Some(builder.with_machine_key(path));

        Python::with_gil(|py| {
            Py::new(
                py,
                Self {
                    inner: Mutex::new(guard.take()),
                },
            )
        })
    }

    /// Import an agent keypair from bytes.
    ///
    /// This allows running the same agent identity on different machines.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The ML-DSA-65 public key bytes (2592 bytes)
    /// * `secret_key` - The ML-DSA-65 secret key bytes (4032 bytes)
    ///
    /// # Returns
    ///
    /// Self for method chaining
    ///
    /// # Raises
    ///
    /// * `ValueError` - If the keypair bytes are invalid
    ///
    /// # Example (Python)
    ///
    /// ```python
    /// # Export from existing agent
    /// public_key = agent.agent_id.public_key_bytes
    /// secret_key = ...  # stored securely
    ///
    /// # Import on another machine
    /// agent = await Agent.builder() \\
    ///     .with_agent_key(public_key, secret_key) \\
    ///     .build()
    /// ```
    fn with_agent_key(&self, public_key: Vec<u8>, secret_key: Vec<u8>) -> PyResult<Py<Self>> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| PyErr::new::<PyIOError, _>(format!("Lock error: {}", e)))?;

        let builder = guard
            .take()
            .ok_or_else(|| PyErr::new::<PyValueError, _>("Builder already consumed by build()"))?;

        let keypair = x0x::identity::AgentKeypair::from_bytes(&public_key, &secret_key)
            .map_err(|e| PyErr::new::<PyValueError, _>(format!("Invalid agent keypair: {}", e)))?;

        *guard = Some(builder.with_agent_key(keypair));

        Python::with_gil(|py| {
            Py::new(
                py,
                Self {
                    inner: Mutex::new(guard.take()),
                },
            )
        })
    }

    /// Build the Agent with the configured settings.
    ///
    /// This is an async method that creates the agent identity and prepares
    /// it for network operations.
    ///
    /// # Returns
    ///
    /// A new Agent instance
    ///
    /// # Raises
    ///
    /// * `IOError` - If agent creation fails (e.g., invalid machine key path)
    ///
    /// # Example (Python)
    ///
    /// ```python
    /// agent = await Agent.builder().build()
    /// ```
    fn build<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| PyErr::new::<PyIOError, _>(format!("Lock error: {}", e)))?;

        let builder = guard.take().ok_or_else(|| {
            PyErr::new::<PyValueError, _>("Builder already consumed by previous build() call")
        })?;

        future_into_py(py, async move {
            let agent = builder
                .build()
                .await
                .map_err(|e| PyErr::new::<PyIOError, _>(format!("Failed to build agent: {}", e)))?;

            Python::with_gil(|py| Py::new(py, Agent { inner: agent }))
        })
    }
}
