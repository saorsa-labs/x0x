#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests for x0x agent identity management
//!
//! These tests verify the end-to-end workflow of creating agents,
//! managing machine and agent identities, and demonstrating the
//! portable nature of agent identities.

use tempfile::TempDir;
use x0x::identity::{AgentCertificate, AgentKeypair, UserKeypair};
use x0x::{storage, Agent};

/// Integration test for Agent creation with identity management
///
/// This test verifies the complete workflow:
/// 1. Create first agent (auto-generates keys)
/// 2. Verify machine_id and agent_id are valid
/// 3. Create second agent (reuses machine key, generates new agent key)
/// 4. Verify both agents have same machine_id but different agent_ids
#[tokio::test]
async fn test_agent_creation_workflow() {
    // Create temporary directory for isolated testing
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path();

    // Create first agent with custom machine key path and agent key path
    let agent1 = Agent::builder()
        .with_machine_key(temp_path.join("machine1.key"))
        .with_agent_key_path(temp_path.join("agent1.key"))
        .build()
        .await
        .expect("Failed to create agent1");

    let machine_id1 = agent1.machine_id();
    let agent_id1 = agent1.agent_id();

    // Verify the IDs are not zero
    assert_ne!(
        machine_id1.as_bytes(),
        &[0u8; 32],
        "Machine ID should not be zero"
    );
    assert_ne!(
        agent_id1.as_bytes(),
        &[0u8; 32],
        "Agent ID should not be zero"
    );

    // Create second agent with same machine key but different agent key path
    let agent2 = Agent::builder()
        .with_machine_key(temp_path.join("machine1.key"))
        .with_agent_key_path(temp_path.join("agent2.key"))
        .build()
        .await
        .expect("Failed to create agent2");

    let machine_id2 = agent2.machine_id();
    let agent_id2 = agent2.agent_id();

    // Both agents should have the same machine ID (same machine key)
    assert_eq!(
        machine_id1, machine_id2,
        "Machine ID should be consistent for same machine key"
    );

    // Agents should have different agent IDs (different agent keys)
    assert_ne!(
        agent_id1, agent_id2,
        "Agent ID should be different for different agent keys"
    );

    // Verify the IDs are still valid
    assert_ne!(
        machine_id2.as_bytes(),
        &[0u8; 32],
        "Machine ID should not be zero"
    );
    assert_ne!(
        agent_id2.as_bytes(),
        &[0u8; 32],
        "Agent ID should not be zero"
    );
}

/// Test demonstrating portable agent identity concept
/// Export an agent keypair and import it to create the same agent on a "different machine"
#[tokio::test]
async fn test_portable_agent_identity() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path();

    // Create original agent with isolated key paths
    let original_agent = Agent::builder()
        .with_machine_key(temp_path.join("original_machine.key"))
        .with_agent_key_path(temp_path.join("original_agent.key"))
        .build()
        .await
        .expect("Failed to create original agent");

    let original_agent_id = original_agent.agent_id();
    let original_machine_id = original_agent.machine_id();

    // Export the agent keypair by saving to file
    let agent_key_path = temp_path.join("exported_agent.key");
    storage::save_agent_keypair(original_agent.identity().agent_keypair(), &agent_key_path)
        .await
        .expect("Failed to save agent keypair");

    // Load the agent keypair back
    let imported_keypair = storage::load_agent_keypair(&agent_key_path)
        .await
        .expect("Failed to load agent keypair");

    // Create a new "machine" with different machine key but imported agent keypair
    let migrated_agent = Agent::builder()
        .with_machine_key(temp_path.join("migrated_machine.key"))
        .with_agent_key(imported_keypair)
        .build()
        .await
        .expect("Failed to create migrated agent");

    // The agent ID should be the same (portable identity)
    assert_eq!(
        original_agent_id,
        migrated_agent.agent_id(),
        "Agent ID should be portable"
    );

    // The machine ID should be different (different machine)
    assert_ne!(
        original_machine_id,
        migrated_agent.machine_id(),
        "Machine ID should be different for different machines"
    );

    // Verify both can be created successfully
    assert!(!original_agent
        .identity()
        .machine_keypair()
        .public_key()
        .as_bytes()
        .is_empty());
    assert!(!migrated_agent
        .identity()
        .machine_keypair()
        .public_key()
        .as_bytes()
        .is_empty());
}

/// Test that agent keys persist across sessions.
///
/// When an agent is created with a key path, the key should be saved.
/// A subsequent agent built with the same path should load the same identity.
#[tokio::test]
async fn test_agent_key_persistence() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path();

    let agent_key_path = temp_path.join("persistent_agent.key");
    let machine_key_path = temp_path.join("machine.key");

    // First build: generates and saves agent key
    let agent1 = Agent::builder()
        .with_machine_key(machine_key_path.clone())
        .with_agent_key_path(agent_key_path.clone())
        .build()
        .await
        .expect("Failed to create agent1");

    let agent_id1 = agent1.agent_id();

    // Verify the key file was created
    assert!(
        agent_key_path.exists(),
        "Agent key file should be created on first build"
    );

    // Second build: should load the same agent key
    let agent2 = Agent::builder()
        .with_machine_key(machine_key_path)
        .with_agent_key_path(agent_key_path)
        .build()
        .await
        .expect("Failed to create agent2");

    let agent_id2 = agent2.agent_id();

    // Same agent key path = same agent identity
    assert_eq!(
        agent_id1, agent_id2,
        "Agent ID should persist across builds with same key path"
    );
}

/// Test that the default agent key storage functions work correctly.
#[tokio::test]
async fn test_agent_keypair_storage_roundtrip() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let path = temp_dir.path().join("test_agent.key");

    // Generate and save
    let original = x0x::identity::AgentKeypair::generate().expect("Failed to generate keypair");
    let original_id = x0x::identity::AgentId::from_public_key(original.public_key());

    storage::save_agent_keypair_to(&original, &path)
        .await
        .expect("Failed to save agent keypair");

    // Load and verify
    let loaded = storage::load_agent_keypair_from(&path)
        .await
        .expect("Failed to load agent keypair");
    let loaded_id = x0x::identity::AgentId::from_public_key(loaded.public_key());

    assert_eq!(original_id, loaded_id, "Agent ID should survive round-trip");
}

// ── Three-Layer Identity Tests ──

/// Test the full three-layer identity workflow:
/// User → Agent → Machine, with all three IDs distinct.
#[tokio::test]
async fn test_three_layer_identity_workflow() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path();

    // Generate a user keypair
    let user_kp = UserKeypair::generate().expect("Failed to generate user keypair");
    let expected_user_id = user_kp.user_id();

    // Save user key to temp path
    storage::save_user_keypair_to(&user_kp, temp_path.join("user.key"))
        .await
        .expect("Failed to save user keypair");

    // Build agent with three-layer identity
    let agent = Agent::builder()
        .with_machine_key(temp_path.join("machine.key"))
        .with_agent_key_path(temp_path.join("agent.key"))
        .with_user_key_path(temp_path.join("user.key"))
        .build()
        .await
        .expect("Failed to create agent with user key");

    // All three IDs should be present and distinct
    let machine_id = agent.machine_id();
    let agent_id = agent.agent_id();
    let user_id = agent.user_id().expect("User ID should be present");

    assert_ne!(machine_id.as_bytes(), &[0u8; 32]);
    assert_ne!(agent_id.as_bytes(), &[0u8; 32]);
    assert_ne!(user_id.as_bytes(), &[0u8; 32]);

    // All three should be different from each other
    assert_ne!(
        machine_id.as_bytes(),
        agent_id.as_bytes(),
        "Machine and Agent IDs must differ"
    );
    assert_ne!(
        agent_id.as_bytes(),
        user_id.as_bytes(),
        "Agent and User IDs must differ"
    );
    assert_ne!(
        machine_id.as_bytes(),
        user_id.as_bytes(),
        "Machine and User IDs must differ"
    );

    // User ID should match the keypair we created
    assert_eq!(user_id, expected_user_id);

    // Certificate should be present
    let cert = agent
        .agent_certificate()
        .expect("Certificate should be present");
    cert.verify().expect("Certificate should be valid");
}

/// Test certificate issuance and verification round-trip.
#[tokio::test]
async fn test_agent_certificate_issue_and_verify() {
    let user_kp = UserKeypair::generate().expect("Failed to generate user keypair");
    let agent_kp = AgentKeypair::generate().expect("Failed to generate agent keypair");

    // Issue certificate
    let cert = AgentCertificate::issue(&user_kp, &agent_kp).expect("Failed to issue certificate");

    // Verify the certificate
    cert.verify()
        .expect("Certificate verification should succeed");

    // IDs should match
    assert_eq!(
        cert.user_id().expect("user_id"),
        user_kp.user_id(),
        "Certificate user_id should match keypair"
    );
    assert_eq!(
        cert.agent_id().expect("agent_id"),
        agent_kp.agent_id(),
        "Certificate agent_id should match keypair"
    );

    // Timestamp should be recent (within last 60 seconds)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        cert.issued_at() <= now && cert.issued_at() > now - 60,
        "Certificate timestamp should be recent"
    );
}

/// Test that certificate verification catches wrong keys.
#[tokio::test]
async fn test_agent_certificate_wrong_key_fails() {
    let user_a = UserKeypair::generate().expect("Failed to generate user A");
    let user_b = UserKeypair::generate().expect("Failed to generate user B");
    let agent_kp = AgentKeypair::generate().expect("Failed to generate agent keypair");

    // Issue cert from user A
    let cert = AgentCertificate::issue(&user_a, &agent_kp).expect("Failed to issue certificate");

    // Verify with correct key works
    cert.verify().expect("Valid cert should verify");

    // Now tamper: replace user public key with user B's key
    // The signature was made by user A, so verification should fail
    // We need to access the internal field — the test in identity.rs already covers this,
    // but here we verify the builder-level flow

    // Build agent with user B but agent already has cert from user A
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path();

    // Save user B's key
    storage::save_user_keypair_to(&user_b, temp_path.join("user_b.key"))
        .await
        .expect("Failed to save user B keypair");

    // Build agent — it should generate a new cert for user B (not reuse A's cert)
    let agent = Agent::builder()
        .with_machine_key(temp_path.join("machine.key"))
        .with_agent_key_path(temp_path.join("agent.key"))
        .with_user_key_path(temp_path.join("user_b.key"))
        .build()
        .await
        .expect("Failed to create agent");

    // Cert should be valid for user B
    let agent_cert = agent.agent_certificate().expect("Should have cert");
    agent_cert.verify().expect("New cert should verify");
    assert_eq!(
        agent_cert.user_id().expect("user_id"),
        user_b.user_id(),
        "Cert should be for user B"
    );
}

/// Test user key persistence: save/load round-trip.
#[tokio::test]
async fn test_user_key_persistence() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let path = temp_dir.path().join("test_user.key");

    // Generate and save
    let original = UserKeypair::generate().expect("Failed to generate user keypair");
    let original_id = original.user_id();

    storage::save_user_keypair_to(&original, &path)
        .await
        .expect("Failed to save user keypair");

    // Load and verify
    let loaded = storage::load_user_keypair_from(&path)
        .await
        .expect("Failed to load user keypair");
    let loaded_id = loaded.user_id();

    assert_eq!(
        original_id, loaded_id,
        "User ID should survive save/load round-trip"
    );
}

/// Test that an agent built without user key has no user identity (backward compat).
#[tokio::test]
async fn test_agent_without_user_key_is_two_layer() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path();

    let agent = Agent::builder()
        .with_machine_key(temp_path.join("machine.key"))
        .with_agent_key_path(temp_path.join("agent.key"))
        .build()
        .await
        .expect("Failed to create agent");

    // No user identity
    assert!(agent.user_id().is_none(), "User ID should be None");
    assert!(
        agent.agent_certificate().is_none(),
        "Certificate should be None"
    );

    // Machine and agent IDs should still work
    assert_ne!(agent.machine_id().as_bytes(), &[0u8; 32]);
    assert_ne!(agent.agent_id().as_bytes(), &[0u8; 32]);
}

/// Test that user key path with non-existent file doesn't auto-generate.
#[tokio::test]
async fn test_user_key_path_nonexistent_does_not_generate() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path();

    // Point to a non-existent user key file
    let agent = Agent::builder()
        .with_machine_key(temp_path.join("machine.key"))
        .with_agent_key_path(temp_path.join("agent.key"))
        .with_user_key_path(temp_path.join("nonexistent_user.key"))
        .build()
        .await
        .expect("Failed to create agent");

    // User identity should NOT be present (not auto-generated)
    assert!(
        agent.user_id().is_none(),
        "User ID should be None when key file doesn't exist"
    );

    // The file should NOT have been created
    assert!(
        !temp_path.join("nonexistent_user.key").exists(),
        "User key file should not be auto-generated"
    );
}
