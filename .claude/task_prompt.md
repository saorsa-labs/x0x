# Task 4: Implement Keypair Management

## Context
x0x project - Phase 1.1, Task 4. Tasks 1-3 are complete (error types, core identity types).

## Task Description
Create MachineKeypair and AgentKeypair structs wrapping ML-DSA-65 keys in src/identity.rs.

## Acceptance Criteria
1. Both keypairs use ant-quic's generate_ml_dsa_keypair()
2. No unsafe, unwrap, or expect
3. Proper error propagation using crate::error::Result
4. Full documentation with rustdoc

## Implementation

Add to src/identity.rs:

```rust
use ant_quic::crypto::raw_public_keys::pqc::{MlDsaPublicKey, MlDsaSecretKey, generate_ml_dsa_keypair};

/// Machine-pinned ML-DSA-65 keypair
pub struct MachineKeypair {
    public_key: MlDsaPublicKey,
    secret_key: MlDsaSecretKey,
}

impl MachineKeypair {
    pub fn generate() -> Result<Self> {
        let (public_key, secret_key) = generate_ml_dsa_keypair()
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
        let (public_key, secret_key) = generate_ml_dsa_keypair()
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

Add tests:
- test_machine_keypair_generation
- test_agent_keypair_generation
- test_machine_keypair_id_derivation
- test_agent_keypair_id_derivation

## ZERO TOLERANCE POLICY
- No errors, no warnings, no unwrap, no expect, no panic, no unsafe
- All tests must pass

## After completion
Run: cargo check, cargo clippy, cargo nextest run
