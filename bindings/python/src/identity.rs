//! Python bindings for x0x identity types.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyType;
use std::hash::{Hash, Hasher};
use x0x::identity::{AgentId as CoreAgentId, MachineId as CoreMachineId};

/// Machine-pinned identity derived from ML-DSA-65 keypair.
///
/// A MachineId is a 32-byte identifier that binds an agent to a specific machine.
/// It is derived from the machine's ML-DSA-65 public key via SHA-256 hashing.
#[pyclass]
#[derive(Clone)]
pub struct MachineId {
    inner: CoreMachineId,
}

#[pymethods]
impl MachineId {
    /// Create a MachineId from a hex-encoded string.
    ///
    /// Args:
    ///     hex_str: A 64-character hex string representing 32 bytes
    ///
    /// Returns:
    ///     MachineId instance
    ///
    /// Raises:
    ///     ValueError: If hex string is invalid or not 32 bytes
    #[classmethod]
    fn from_hex(_cls: &PyType, hex_str: &str) -> PyResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| PyValueError::new_err(format!("Invalid hex encoding: {e}")))?;

        if bytes.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "MachineId must be 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self {
            inner: CoreMachineId(array),
        })
    }

    /// Convert MachineId to hex string.
    ///
    /// Returns:
    ///     64-character hex string
    fn to_hex(&self) -> String {
        hex::encode(self.inner.as_bytes())
    }

    fn __str__(&self) -> String {
        hex::encode(self.inner.as_bytes())
    }

    fn __repr__(&self) -> String {
        format!("MachineId('{}')", hex::encode(&self.inner.as_bytes()[..8]))
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.inner.hash(&mut hasher);
        hasher.finish()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl From<CoreMachineId> for MachineId {
    fn from(inner: CoreMachineId) -> Self {
        Self { inner }
    }
}

/// Portable agent identity derived from ML-DSA-65 keypair.
///
/// An AgentId is a 32-byte identifier that represents an agent's persistent identity
/// across machines. It is derived from the agent's ML-DSA-65 public key via SHA-256.
#[pyclass]
#[derive(Clone)]
pub struct AgentId {
    inner: CoreAgentId,
}

#[pymethods]
impl AgentId {
    /// Create an AgentId from a hex-encoded string.
    ///
    /// Args:
    ///     hex_str: A 64-character hex string representing 32 bytes
    ///
    /// Returns:
    ///     AgentId instance
    ///
    /// Raises:
    ///     ValueError: If hex string is invalid or not 32 bytes
    #[classmethod]
    fn from_hex(_cls: &PyType, hex_str: &str) -> PyResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| PyValueError::new_err(format!("Invalid hex encoding: {e}")))?;

        if bytes.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "AgentId must be 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self {
            inner: CoreAgentId(array),
        })
    }

    /// Convert AgentId to hex string.
    ///
    /// Returns:
    ///     64-character hex string
    fn to_hex(&self) -> String {
        hex::encode(self.inner.as_bytes())
    }

    fn __str__(&self) -> String {
        hex::encode(self.inner.as_bytes())
    }

    fn __repr__(&self) -> String {
        format!("AgentId('{}')", hex::encode(&self.inner.as_bytes()[..8]))
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.inner.hash(&mut hasher);
        hasher.finish()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl From<CoreAgentId> for AgentId {
    fn from(inner: CoreAgentId) -> Self {
        Self { inner }
    }
}
