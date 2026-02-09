use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Agent identity - 32-byte public key hash
#[napi]
pub struct AgentId {
    inner: x0x::identity::AgentId,
}

#[napi]
impl AgentId {
    /// Convert AgentId to hex string representation
    #[napi(js_name = "toString")]
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.inner.as_bytes())
    }

    /// Create AgentId from hex string
    #[napi(factory)]
    pub fn from_string(s: String) -> Result<Self> {
        let bytes = hex::decode(&s)
            .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid hex: {e}")))?;

        if bytes.len() != 32 {
            return Err(Error::new(Status::InvalidArg, "AgentId must be 32 bytes"));
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);

        Ok(AgentId {
            inner: x0x::identity::AgentId(array),
        })
    }

    /// Get raw bytes
    #[napi]
    pub fn as_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }
}

impl From<x0x::identity::AgentId> for AgentId {
    fn from(inner: x0x::identity::AgentId) -> Self {
        AgentId { inner }
    }
}

impl From<AgentId> for x0x::identity::AgentId {
    fn from(id: AgentId) -> Self {
        id.inner
    }
}

/// Machine identity - 32-byte hardware-tied identity
#[napi]
pub struct MachineId {
    inner: x0x::identity::MachineId,
}

#[napi]
impl MachineId {
    /// Convert MachineId to hex string representation
    #[napi(js_name = "toString")]
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.inner.as_bytes())
    }

    /// Create MachineId from hex string
    #[napi(factory)]
    pub fn from_string(s: String) -> Result<Self> {
        let bytes = hex::decode(&s)
            .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid hex: {e}")))?;

        if bytes.len() != 32 {
            return Err(Error::new(Status::InvalidArg, "MachineId must be 32 bytes"));
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);

        Ok(MachineId {
            inner: x0x::identity::MachineId(array),
        })
    }

    /// Get raw bytes
    #[napi]
    pub fn as_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }
}

impl From<x0x::identity::MachineId> for MachineId {
    fn from(inner: x0x::identity::MachineId) -> Self {
        MachineId { inner }
    }
}

impl From<MachineId> for x0x::identity::MachineId {
    fn from(id: MachineId) -> Self {
        id.inner
    }
}
