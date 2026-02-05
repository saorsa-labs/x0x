# Phase 1.1 Plan: Agent Identity & Key Management

## Overview
Build the cryptographic identity system for x0x agents using ML-DSA-65 post-quantum signatures. Each agent has two identities: a machine-pinned identity (for QUIC transport authentication via ant-quic) and a portable agent identity (for cross-machine agent persistence). Both use ML-DSA-65 keypairs with PeerIds derived via SHA-256 hashing.

## Dependencies
- **ant-quic v0.21.2**: Provides ML-DSA-65 key generation, PeerId derivation, and QUIC transport
  - Location: `../ant-quic`
  - Key APIs: `generate_ml_dsa_keypair()`, `derive_peer_id_from_public_key()`
- **saorsa-pqc v0.4**: Post-quantum cryptography primitives (already used by ant-quic)
  - Types: `MlDsaPublicKey`, `MlDsaSecretKey`, `MlDsaSignature`

## Tasks

### Task 1: Add Dependencies to Cargo.toml
**Files**: `Cargo.toml`

**Description**: Add ant-quic and supporting dependencies for identity management and storage.

**Changes**:
```toml
[dependencies]
ant-quic = { version = "0.21.2", path = "../ant-quic" }
saorsa-pqc = "0.4"
blake3 = "1.5"
serde = { version = "1.0", features = ["derive"] }
thiserror = "2.0"
tokio = { version = "1", features = ["full"] }
```

**Acceptance Criteria**:
- `cargo check` passes with no warnings
- Dependencies resolve correctly from local path

**Estimated Lines**: ~10

---

### Task 2: Define Error Types
**Files**: `src/error.rs` (new)

**Description**: Create comprehensive error types for identity operations following Rust best practices. No panics, no unwrap, Result-based error handling.

**Implementation**:
```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("failed to generate keypair: {0}")]
    KeyGeneration(String),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid secret key: {0}")]
    InvalidSecretKey(String),

    #[error("PeerId verification failed")]
    PeerIdMismatch,

    #[error("key storage error: {0}")]
    Storage(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, IdentityError>;
```

**Acceptance Criteria**:
- All error variants cover identity operations from ROADMAP
- Implements Display, Debug, Error traits
- No panic paths
- `cargo clippy` passes with zero warnings

**Estimated Lines**: ~40

---

### Task 3: Define Core Identity Types
**Files**: `src/identity.rs` (new), `src/lib.rs` (export module)

**Description**: Create MachineId, AgentId, and PeerId types wrapping ant-quic's PeerId derivation.

**Implementation**:
```rust
use ant_quic::crypto::raw_public_keys::pqc::{
    MlDsaPublicKey, MlDsaSecretKey, derive_peer_id_from_public_key,
};
use ant_quic::nat_traversal_api::PeerId as AntQuicPeerId;
use serde::{Serialize, Deserialize};

/// Machine-pinned identity derived from ML-DSA-65 keypair
/// SHA-256(domain || pubkey) → 32-byte PeerId
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MachineId(pub [u8; 32]);

/// Portable agent identity derived from ML-DSA-65 keypair
/// SHA-256(domain || pubkey) → 32-byte PeerId
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub [u8; 32]);

impl MachineId {
    pub fn from_public_key(pubkey: &MlDsaPublicKey) -> Self {
        let peer_id = derive_peer_id_from_public_key(pubkey);
        Self(peer_id.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AgentId {
    pub fn from_public_key(pubkey: &MlDsaPublicKey) -> Self {
        let peer_id = derive_peer_id_from_public_key(pubkey);
        Self(peer_id.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
```

**Acceptance Criteria**:
- MachineId and AgentId wrap 32-byte SHA-256 hashes
- Both derive from ML-DSA-65 public keys via ant-quic
- Serializable for storage
- Zero unwrap/expect calls
- Full rustdoc comments

**Estimated Lines**: ~60

---

### Task 4: Implement Keypair Management
**Files**: `src/identity.rs` (extend)

**Description**: Create MachineKeypair and AgentKeypair structs wrapping ML-DSA-65 keys.

**Implementation**:
```rust
use crate::error::{IdentityError, Result};

/// Machine-pinned ML-DSA-65 keypair
pub struct MachineKeypair {
    public_key: MlDsaPublicKey,
    secret_key: MlDsaSecretKey,
}

impl MachineKeypair {
    pub fn generate() -> Result<Self> {
        let (public_key, secret_key) = ant_quic::crypto::raw_public_keys::pqc::generate_ml_dsa_keypair()
            .map_err(|e| IdentityError::KeyGeneration(format!("{:?}", e)))?;
        Ok(Self { public_key, secret_key })
    }

    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }

    pub fn machine_id(&self) -> MachineId {
        MachineId::from_public_key(&self.public_key)
    }
}

/// Portable agent ML-DSA-65 keypair
pub struct AgentKeypair {
    public_key: MlDsaPublicKey,
    secret_key: MlDsaSecretKey,
}

impl AgentKeypair {
    pub fn generate() -> Result<Self> {
        let (public_key, secret_key) = ant_quic::crypto::raw_public_keys::pqc::generate_ml_dsa_keypair()
            .map_err(|e| IdentityError::KeyGeneration(format!("{:?}", e)))?;
        Ok(Self { public_key, secret_key })
    }

    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }

    pub fn agent_id(&self) -> AgentId {
        AgentId::from_public_key(&self.public_key)
    }
}
```

**Acceptance Criteria**:
- Both keypairs use ant-quic's `generate_ml_dsa_keypair()`
- No unsafe, unwrap, or expect
- Proper error propagation
- Full documentation

**Estimated Lines**: ~70

---

### Task 5: Implement PeerId Verification
**Files**: `src/identity.rs` (extend)

**Description**: Add verification functions to detect key substitution attacks.

**Implementation**:
```rust
impl MachineId {
    /// Verify this MachineId was derived from the given public key
    pub fn verify(&self, pubkey: &MlDsaPublicKey) -> Result<()> {
        let derived = Self::from_public_key(pubkey);
        if *self == derived {
            Ok(())
        } else {
            Err(IdentityError::PeerIdMismatch)
        }
    }
}

impl AgentId {
    /// Verify this AgentId was derived from the given public key
    pub fn verify(&self, pubkey: &MlDsaPublicKey) -> Result<()> {
        let derived = Self::from_public_key(pubkey);
        if *self == derived {
            Ok(())
        } else {
            Err(IdentityError::PeerIdMismatch)
        }
    }
}
```

**Acceptance Criteria**:
- Detects mismatched IDs vs public keys
- Returns proper errors, never panics
- Documented with security rationale

**Estimated Lines**: ~30

---

### Task 6: Define Identity Struct
**Files**: `src/identity.rs` (extend)

**Description**: Create the unified Identity struct combining machine and agent identities.

**Implementation**:
```rust
/// Complete x0x agent identity
pub struct Identity {
    machine_keypair: MachineKeypair,
    agent_keypair: AgentKeypair,
}

impl Identity {
    /// Create a new identity with freshly generated keys
    pub fn generate() -> Result<Self> {
        Ok(Self {
            machine_keypair: MachineKeypair::generate()?,
            agent_keypair: AgentKeypair::generate()?,
        })
    }

    pub fn machine_id(&self) -> MachineId {
        self.machine_keypair.machine_id()
    }

    pub fn agent_id(&self) -> AgentId {
        self.agent_keypair.agent_id()
    }

    pub fn machine_keypair(&self) -> &MachineKeypair {
        &self.machine_keypair
    }

    pub fn agent_keypair(&self) -> &AgentKeypair {
        &self.agent_keypair
    }
}
```

**Acceptance Criteria**:
- Wraps both machine and agent keypairs
- Generate creates fresh ML-DSA-65 keys
- All accessors return references (no cloning of secret keys)
- Zero warnings

**Estimated Lines**: ~40

---

### Task 7: Implement Key Storage Serialization
**Files**: `src/storage.rs` (new)

**Description**: Serialize keypairs for persistent storage. Use raw bytes, not base64 (efficiency).

**Implementation**:
```rust
use crate::error::{IdentityError, Result};
use crate::identity::{AgentKeypair, MachineKeypair};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct SerializedKeypair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

pub fn serialize_machine_keypair(kp: &MachineKeypair) -> Result<Vec<u8>> {
    let data = SerializedKeypair {
        public_key: kp.public_key().as_bytes().to_vec(),
        secret_key: kp.secret_key().as_bytes().to_vec(),
    };
    bincode::serialize(&data).map_err(|e| IdentityError::Serialization(e.to_string()))
}

pub fn deserialize_machine_keypair(bytes: &[u8]) -> Result<MachineKeypair> {
    let data: SerializedKeypair = bincode::deserialize(bytes)
        .map_err(|e| IdentityError::Serialization(e.to_string()))?;
    MachineKeypair::from_bytes(&data.public_key, &data.secret_key)
}

// Similar for AgentKeypair...
```

**Acceptance Criteria**:
- Serializes to compact binary (bincode or similar)
- Round-trip identity: deserialize(serialize(kp)) == kp
- Proper error handling for invalid data
- Add bincode dependency to Cargo.toml

**Estimated Lines**: ~60

---

### Task 8: Implement Secure File Storage
**Files**: `src/storage.rs` (extend)

**Description**: Store keys in `~/.x0x/machine.key` and allow agent key import/export. No encryption for MVP (OS filesystem permissions).

**Implementation**:
```rust
use std::path::{Path, PathBuf};
use tokio::fs;

const X0X_DIR: &str = ".x0x";
const MACHINE_KEY_FILE: &str = "machine.key";

async fn x0x_dir() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| IdentityError::Storage(std::io::Error::new(
            std::io::ErrorKind::NotFound, "home directory not found"
        )))?;
    Ok(home.join(X0X_DIR))
}

pub async fn save_machine_keypair(kp: &MachineKeypair) -> Result<()> {
    let dir = x0x_dir().await?;
    fs::create_dir_all(&dir).await?;
    let path = dir.join(MACHINE_KEY_FILE);
    let bytes = serialize_machine_keypair(kp)?;
    fs::write(&path, bytes).await?;
    Ok(())
}

pub async fn load_machine_keypair() -> Result<MachineKeypair> {
    let path = x0x_dir().await?.join(MACHINE_KEY_FILE);
    let bytes = fs::read(&path).await?;
    deserialize_machine_keypair(&bytes)
}

pub async fn machine_keypair_exists() -> bool {
    let Ok(path) = x0x_dir().await else { return false };
    path.join(MACHINE_KEY_FILE).exists()
}
```

**Acceptance Criteria**:
- Creates `~/.x0x/` directory on first run
- Stores machine key persistently
- Agent keys are importable/exportable (separate functions)
- Async I/O with tokio
- Add dirs crate dependency

**Estimated Lines**: ~80

---

### Task 9: Update Agent Builder with Identity
**Files**: `src/lib.rs` (modify Agent and AgentBuilder)

**Description**: Integrate Identity into Agent struct and builder API per ROADMAP requirements.

**Implementation**:
```rust
use crate::identity::Identity;
use crate::error::{IdentityError, Result};

pub struct Agent {
    identity: Identity,
}

pub struct AgentBuilder {
    machine_key_path: Option<PathBuf>,
    agent_keypair: Option<AgentKeypair>,
}

impl AgentBuilder {
    pub fn with_machine_key<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.machine_key_path = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn with_agent_key(mut self, keypair: AgentKeypair) -> Self {
        self.agent_keypair = Some(keypair);
        self
    }

    pub async fn build(self) -> Result<Agent> {
        let machine_keypair = if let Some(path) = self.machine_key_path {
            // Load from custom path
            load_machine_keypair_from(&path).await?
        } else if machine_keypair_exists().await {
            load_machine_keypair().await?
        } else {
            let kp = MachineKeypair::generate()?;
            save_machine_keypair(&kp).await?;
            kp
        };

        let agent_keypair = self.agent_keypair
            .map(Ok)
            .unwrap_or_else(AgentKeypair::generate)?;

        let identity = Identity { machine_keypair, agent_keypair };
        Ok(Agent { identity })
    }
}
```

**Acceptance Criteria**:
- Agent wraps Identity
- Builder supports custom machine key path
- Builder supports imported agent keypair
- Auto-generates and saves machine key if not found
- All async, zero blocking I/O

**Estimated Lines**: ~60

---

### Task 10: Write Unit Tests for Identity
**Files**: `src/identity.rs` (tests module)

**Description**: TDD tests for all identity operations. Property-based testing would be overkill for crypto wrappers.

**Tests**:
- `test_machine_id_derivation`: MachineId derives consistently from same pubkey
- `test_agent_id_derivation`: AgentId derives consistently
- `test_machine_id_verification_success`: Valid pubkey passes verification
- `test_machine_id_verification_failure`: Different pubkey fails verification
- `test_keypair_generation`: Keypair generation succeeds
- `test_identity_generation`: Full Identity generation works
- `test_different_keys_different_ids`: Two generated keypairs have different IDs

**Acceptance Criteria**:
- All tests pass with `cargo nextest run`
- Zero warnings
- Tests use ant-quic's test utilities if available

**Estimated Lines**: ~80

---

### Task 11: Write Tests for Storage
**Files**: `src/storage.rs` (tests module)

**Description**: Test key persistence and serialization round-trips.

**Tests**:
- `test_keypair_serialization_roundtrip`: serialize → deserialize == original
- `test_save_and_load_machine_keypair`: Save to temp file, load, verify ID matches
- `test_machine_keypair_exists`: Correctly detects presence/absence
- `test_invalid_deserialization`: Corrupted bytes return error, not panic

**Acceptance Criteria**:
- All storage operations tested
- Uses `tempfile` crate for isolated test directories
- Zero unwrap in test code
- All tests pass

**Estimated Lines**: ~70

---

### Task 12: Integration Test - Agent Creation
**Files**: `tests/identity_integration.rs` (new)

**Description**: End-to-end test of Agent creation with identity management.

**Test Flow**:
1. Create agent with builder (auto-generates keys)
2. Verify machine_id and agent_id are valid
3. Create second agent (reuses machine key, generates new agent key)
4. Verify both agents have same machine_id but different agent_ids

**Acceptance Criteria**:
- Tests full workflow from ROADMAP
- Runs in isolated temp directory
- Cleanup after test
- Demonstrates portable agent identity concept

**Estimated Lines**: ~60

---

### Task 13: Documentation Pass
**Files**: `src/identity.rs`, `src/storage.rs`, `src/error.rs`, `README.md`

**Description**: Ensure all public APIs have complete rustdoc. Update README with identity section.

**README Section**:
```markdown
## Identity System

x0x uses dual ML-DSA-65 identities:
- **Machine Identity**: Tied to your computer (stored in `~/.x0x/machine.key`)
- **Agent Identity**: Portable across machines (import/export supported)

Both use post-quantum ML-DSA-65 signatures with PeerIds derived via SHA-256.
```

**Acceptance Criteria**:
- `cargo doc --no-deps` builds with zero warnings
- All public functions documented with examples
- Security properties explained (PeerId verification)
- README updated

**Estimated Lines**: ~40 (docs)

---

## Summary

**Total Tasks**: 13
**Estimated Total Lines**: ~730
**Average per Task**: ~56 lines

**Key Technical Decisions**:
1. Use ant-quic's ML-DSA-65 implementation directly (no duplication)
2. No encryption for MVP (rely on OS filesystem permissions)
3. Async I/O with tokio throughout
4. Bincode for serialization (compact, fast)
5. Zero unwrap/expect/panic policy enforced
6. Builder pattern for Agent configuration per ROADMAP

**Post-Phase Integration**:
Phase 1.2 (Network Transport) will use `Identity.machine_keypair()` to configure ant-quic's Node API for QUIC authentication.
