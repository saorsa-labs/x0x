//! Integration tests for x0x agent identity management
//!
//! These tests verify the end-to-end workflow of creating agents,
//! managing machine and agent identities, and demonstrating the
//! portable nature of agent identities.

use tempfile::TempDir;
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

    // Create first agent with custom machine key path
    let agent1 = Agent::builder()
        .with_machine_key(temp_path.join("machine1.key"))
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

    // Create second agent with same machine key (should reuse)
    let agent2 = Agent::builder()
        .with_machine_key(temp_path.join("machine1.key"))
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

    // Create original agent
    let original_agent = Agent::builder()
        .with_machine_key(temp_path.join("original_machine.key"))
        .build()
        .await
        .expect("Failed to create original agent");

    let original_agent_id = original_agent.agent_id();
    let original_machine_id = original_agent.machine_id();

    // Export the agent keypair by serializing it
    let _agent_keypair_bytes =
        storage::serialize_agent_keypair(original_agent.identity().agent_keypair())
            .expect("Failed to serialize agent keypair");

    // Save to file
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
