# Phase 1.5: MLS Group Encryption - Implementation Plan

**Phase**: 1.5
**Name**: MLS Group Encryption
**Status**: Planning
**Created**: 2026-02-05
**Estimated Tasks**: 7

---

## Overview

Integrate MLS (Messaging Layer Security) for private, end-to-end encrypted group communications. This phase adds encryption to task lists and presence beacons, allowing agents to collaborate securely within groups.

**Key Technologies:**
- MLS (RFC 9420) for group key management
- ChaCha20-Poly1305 for AEAD encryption
- Forward secrecy and post-compromise security
- Per-epoch key derivation

---

## Task Breakdown

### Task 1: Define MLS Error Types
**File**: `src/mls/error.rs`

Define error types for MLS operations:

```rust
#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    #[error("group not found: {0}")]
    GroupNotFound(String),

    #[error("member not in group: {0}")]
    MemberNotInGroup(String),

    #[error("invalid key material")]
    InvalidKeyMaterial,

    #[error("epoch mismatch: current {current}, received {received}")]
    EpochMismatch { current: u64, received: u64 },

    #[error("encryption error: {0}")]
    EncryptionError(String),

    #[error("decryption error: {0}")]
    DecryptionError(String),

    #[error("MLS operation failed: {0}")]
    MlsOperation(String),
}

pub type Result<T> = std::result::Result<T, MlsError>;
```

**Requirements:**
- Use `thiserror` for error derivation
- Clear error messages for debugging
- No unwrap/expect

**Tests:**
- Error creation and Display formatting

---

### Task 2: Implement MLS Group Context
**File**: `src/mls/group.rs`

Create MLS group data structures:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsGroupContext {
    group_id: Vec<u8>,
    epoch: u64,
    tree_hash: Vec<u8>,
    confirmed_transcript_hash: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MlsGroup {
    group_id: Vec<u8>,
    context: MlsGroupContext,
    members: HashMap<AgentId, MlsMemberInfo>,
    pending_commits: Vec<MlsCommit>,
    epoch: u64,
}

impl MlsGroup {
    pub fn new(group_id: Vec<u8>, initiator: AgentId) -> Result<Self>;
    pub fn add_member(&mut self, member: AgentId) -> Result<MlsCommit>;
    pub fn remove_member(&mut self, member: AgentId) -> Result<MlsCommit>;
    pub fn commit() -> Result<MlsCommit>;
    pub fn apply_commit(&mut self, commit: &MlsCommit) -> Result<()>;
    pub fn current_epoch(&self) -> u64;
}
```

**Requirements:**
- Track group membership
- Manage epochs and key rotation
- Proper error handling for invalid operations

**Tests:**
- Group creation
- Member addition/removal
- Epoch increment on commits

---

### Task 3: Implement MLS Key Derivation
**File**: `src/mls/keys.rs`

Implement key schedule for deriving encryption keys from MLS:

```rust
#[derive(Debug, Clone)]
pub struct MlsKeySchedule {
    epoch: u64,
    psk_id_hash: Vec<u8>,
    secret: Vec<u8>,
    key: Vec<u8>,
    base_nonce: Vec<u8>,
}

impl MlsKeySchedule {
    pub fn from_group(group: &MlsGroup) -> Result<Self>;
    pub fn encryption_key(&self) -> &[u8];
    pub fn base_nonce(&self) -> &[u8];
    pub fn derive_nonce(&self, counter: u64) -> Vec<u8>;
}
```

**Requirements:**
- Derive keys from group secrets
- Support nonce generation for each message
- Support key rotation on epoch change

**Tests:**
- Key derivation is deterministic
- Different epochs produce different keys
- Nonce is unique per counter

---

### Task 4: Implement MLS Message Encryption/Decryption
**File**: `src/mls/cipher.rs`

Implement ChaCha20-Poly1305 encryption for MLS:

```rust
pub struct MlsCipher {
    key: Vec<u8>,
    base_nonce: Vec<u8>,
}

impl MlsCipher {
    pub fn new(key: Vec<u8>, base_nonce: Vec<u8>) -> Self;

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8], counter: u64) -> Result<Vec<u8>>;

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
        counter: u64,
    ) -> Result<Vec<u8>>;
}
```

**Requirements:**
- Use `chacha20poly1305` crate
- Per-message nonce from counter
- Authenticated encryption
- Proper error handling for decryption failures

**Tests:**
- Encrypt/decrypt round-trip
- Authentication tag verification
- Different counters produce different ciphertexts

---

### Task 5: Implement MLS Welcome Flow
**File**: `src/mls/welcome.rs`

Implement MLS Welcome message for inviting members:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsWelcome {
    group_id: Vec<u8>,
    epoch: u64,
    encrypted_group_secrets: HashMap<AgentId, Vec<u8>>,
    tree: Vec<u8>,
    confirmation_tag: Vec<u8>,
}

impl MlsWelcome {
    pub fn create(group: &MlsGroup, invitee: &AgentId) -> Result<Self>;
    pub fn verify(&self) -> Result<()>;
    pub fn accept(&self, agent_id: &AgentId) -> Result<MlsGroupContext>;
}
```

**Requirements:**
- Encrypt group secrets per invitee
- Include tree for new member to build state
- Verification of welcome authenticity
- Proper error handling

**Tests:**
- Welcome creation and verification
- Invitee can decrypt welcome
- Invalid welcomes rejected

---

### Task 6: Integrate Encryption with CRDT Task Lists
**File**: `src/crdt/encrypted.rs`

Add encryption layer to task list deltas:

```rust
pub struct EncryptedTaskListDelta {
    group_id: Vec<u8>,
    epoch: u64,
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
    authentication_tag: Vec<u8>,
}

impl EncryptedTaskListDelta {
    pub fn encrypt(
        delta: &TaskListDelta,
        group: &MlsGroup,
        cipher: &MlsCipher,
    ) -> Result<Self>;

    pub fn decrypt(&self, cipher: &MlsCipher) -> Result<TaskListDelta>;
}
```

**Requirements:**
- Encrypt task list deltas with group keys
- Include group_id and epoch in ciphertext
- Proper authentication
- Backward compatible with unencrypted lists

**Tests:**
- Encrypt/decrypt round-trip
- Different epochs require different keys
- Invalid ciphertexts rejected

---

### Task 7: Write Integration Tests for MLS Groups
**File**: `tests/mls_integration.rs`

Comprehensive integration tests for MLS:

```rust
#[tokio::test]
async fn test_group_creation() { }

#[tokio::test]
async fn test_member_addition() { }

#[tokio::test]
async fn test_member_removal() { }

#[tokio::test]
async fn test_key_rotation() { }

#[tokio::test]
async fn test_forward_secrecy() { }

#[tokio::test]
async fn test_encrypted_task_list_sync() { }

#[tokio::test]
async fn test_multi_agent_group_operations() { }
```

**Requirements:**
- Test group lifecycle
- Test member join/leave
- Test encryption/decryption
- Test key rotation
- No unwrap in test setup
- All tests must pass

---

## Module Structure

Create new module in `src/`:

```
src/mls/
├── mod.rs           // Module declarations
├── error.rs         // Task 1: MlsError type
├── group.rs         // Task 2: MlsGroup struct
├── keys.rs          // Task 3: Key schedule
├── cipher.rs        // Task 4: Encryption/decryption
├── welcome.rs       // Task 5: Welcome messages
└── encrypted.rs     // Task 6: Encrypted CRDT
```

Update `src/lib.rs`:
```rust
pub mod mls;
pub use mls::{MlsGroup, MlsGroupContext, MlsError};
```

---

## Dependencies

Add to `Cargo.toml`:

```toml
[dependencies]
chacha20poly1305 = "0.10"
mls = { version = "0.10" }  # Or use rustls-mls when available
```

Already present:
- `serde`, `thiserror`, `tokio`, `blake3`

---

## Success Criteria

- [ ] Zero compilation errors
- [ ] Zero clippy warnings
- [ ] All integration tests pass
- [ ] No .unwrap()/.expect() in production code
- [ ] Forward secrecy demonstrated in tests
- [ ] Key rotation works correctly
- [ ] Encrypted task lists can be synced
- [ ] Documentation complete for all public APIs

---

## Implementation Notes

**MLS vs Full RFC 9420**: This phase implements MLS-inspired group encryption
without requiring a full RFC 9420 library (which may not be mature enough). We use:
- Group context tracking
- Epoch-based key derivation
- ChaCha20-Poly1305 for AEAD
- Simple tree management (not full ratchet tree initially)

**Integration Strategy**:
1. Start with error types and group structures
2. Implement key schedule and cipher
3. Test encryption with synthetic groups
4. Integrate with real groups via Welcome messages
5. Encrypt task list deltas
6. End-to-end integration tests

---

**Total Tasks**: 7
**Estimated Duration**: 5-7 days
**Prerequisites**: Phase 1.4 complete (CRDT task lists)

