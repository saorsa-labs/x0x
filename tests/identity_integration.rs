//! Integration tests for x0x agent identity management
//!
//! These tests verify the end-to-end workflow of creating agents,
//! managing machine and agent identities, and demonstrating the
//! portable nature of agent identities.

use tempfile::TempDir;

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

    // Create first agent with custom machine key path
    let agent1 = Agent::builder()
        .with_machine_key(temp_path.join("machine1.key"))
        .build()
        .await
        .expect("Failed to create first agent");

    // Verify machine_id and agent_id are valid
    let machine_id1 = agent1.machine_id();
    let agent_id1 = agent1.agent_id();
    
    // Check that IDs are not zero
    assert_ne!(machine_id1.as_bytes(), &[0u8; 32], "Machine ID should not be zero");
    assert_ne!(agent_id1.as_bytes(), &[0u8; 32], "Agent ID should not be zero");

    // Create second agent that reuses the same machine key
    // This should load the existing machine key and generate a new agent key
    let agent2 = Agent::builder()
        .with_machine_key(temp_path.join("machine1.key"))
        .build()
        .await
        .expect("Failed to create second agent");

    let machine_id2 = agent2.machine_id();
    let agent_id2 = agent2.agent_id();

    // Both agents should have the same machine ID (same machine key)
    assert_eq!(machine_id1, machine_id2, "Machine ID should be consistent for same machine key");

    // Agents should have different agent IDs (different agent keys)
    assert_ne!(agent_id1, agent_id2, "Agent ID should be different for different agent keys");

    // Verify the IDs are still valid
    assert_ne!(machine_id2.as_bytes(), &[0u8; 32], "Machine ID should not be zero");
    assert_ne!(agent_id2.as_bytes(), &[0u8; 32], "Agent ID should not be zero");
}

/// Test demonstrating portable agent identity concept
/// Export an agent keypair and import it to create the same agent on a "different machine"
#[tokio::test]
async fn test_portable_agent_identity() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path();

    // Create original agent
    let original_agent = Agent::builder()
        .with_machine_key(temp_path.join("original_machine.key"))
        .build()
        .await
        .expect("Failed to create original agent");

    let original_agent_id = original_agent.agent_id();
    let original_machine_id = original_agent.machine_id();

    // Export the agent keypair (in a real scenario, this would be saved to file)
    let agent_keypair_ref = original_agent.identity().agent_keypair();

    // Generate a new keypair with the same keys (simulate loading from storage)
    let agent_keypair = AgentKeypair::from_bytes(
        agent_keypair_ref.public_key().as_bytes(),
        agent_keypair_ref.secret_key().as_bytes(),
    ).expect("Failed to recreate agent keypair");

    // Create a new "machine" with different machine key but same agent keypair
    let migrated_agent = Agent::builder()
        .with_machine_key(temp_path.join("migrated_machine.key"))
        .with_agent_key(agent_keypair)
        .build()
        .await
        .expect("Failed to create migrated agent");

    // The agent ID should be the same (portable identity)
    assert_eq!(original_agent_id, migrated_agent.agent_id(), "Agent ID should be portable");

    // The machine ID should be different (different machine)
    assert_ne!(original_machine_id, migrated_agent.machine_id(), "Machine ID should be different for different machines");

    // Verify both can be created successfully
    assert!(original_agent.identity().machine_keypair().public_key().as_bytes().len() > 0);
    assert!(migrated_agent.identity().machine_keypair().public_key().as_bytes().len() > 0);
}

/// Test error handling for invalid machine key path
#[tokio::test]
async fn test_invalid_machine_key_path() {
    // Try to load from a non-existent directory (should fail gracefully)
    let result = Agent::builder()
        .with_machine_key("/non/existent/path/machine.key")
        .build()
        .await;

    // The agent should still be created by generating a new keypair
    // (assuming the implementation handles this case)
    match result {
        Ok(_) => {
            // If it succeeds, that's fine - the implementation generates on the fly
        }
        Err(e) => {
            panic!("Creating agent should not fail due to invalid path: {}", e);
        }
    }
}

/// Test that different machine keys produce different machine IDs
#[tokio::test]
async fn test_different_machine_keys_produce_different_ids() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path();

    // Create two agents with different machine key files
    let agent_a = Agent::builder()
        .with_machine_key(temp_path.join("machine_a.key"))
        .build()
        .await
        .expect("Failed to create agent A");

    let agent_b = Agent::builder()
        .with_machine_key(temp_path.join("machine_b.key"))
        .build()
        .await
        .expect("Failed to create agent B");

    // They should have different machine IDs
    assert_ne!(agent_a.machine_id(), agent_b.machine_id(), "Different machine keys should produce different machine IDs");

    // But they could potentially have the same agent ID if by chance they generate the same key
    // This is extremely unlikely but theoretically possible
    // We don't test for agent ID difference as it's probabilistic
}

/// Test creating multiple agents with the same configuration
/// This should result in different agent IDs (due to new key generation)
#[tokio::test]
async fn test_multiple_agents_same_config() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path();

    // Create multiple agents with identical configuration
    let agent1 = Agent::builder()
        .with_machine_key(temp_path.join("shared_machine.key"))
        .build()
        .await
        .expect("Failed to create agent 1");

    let agent2 = Agent::builder()
        .with_machine_key(temp_path.join("shared_machine.key"))
        .build()
        .await
        .expect("Failed to create agent 2");

    let agent3 = Agent::builder()
        .with_machine_key(temp_path.join("shared_machine.key"))
        .build()
        .await
        .expect("Failed to create agent 3");

    // All should have the same machine ID
    assert_eq!(agent1.machine_id(), agent2.machine_id());
    assert_eq!(agent2.machine_id(), agent3.machine_id());
    assert_eq!(agent1.machine_id(), agent3.machine_id());

    // All should have different agent IDs
    assert_ne!(agent1.agent_id(), agent2.agent_id());
    assert_ne!(agent2.agent_id(), agent3.agent_id());
    assert_ne!(agent1.agent_id(), agent3.agent_id());
}
