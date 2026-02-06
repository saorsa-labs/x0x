"""
Tests for Agent and AgentBuilder Python bindings.
"""

import pytest
import pytest_asyncio
import tempfile
import os
from pathlib import Path

# Import x0x types
from x0x import Agent, AgentBuilder, MachineId, AgentId


class TestAgentBuilder:
    """Test Agent builder pattern functionality."""

    @pytest.mark.asyncio
    async def test_basic_build(self):
        """Test basic agent creation with default settings."""
        agent = await Agent.builder().build()
        assert agent is not None
        assert isinstance(agent, Agent)

    @pytest.mark.asyncio
    async def test_machine_id_property(self):
        """Test that agent.machine_id returns a MachineId."""
        agent = await Agent.builder().build()
        machine_id = agent.machine_id
        assert isinstance(machine_id, MachineId)
        # Verify it's a valid hex string
        hex_str = machine_id.to_hex()
        assert len(hex_str) == 64  # SHA-256 = 32 bytes = 64 hex chars

    @pytest.mark.asyncio
    async def test_agent_id_property(self):
        """Test that agent.agent_id returns an AgentId."""
        agent = await Agent.builder().build()
        agent_id = agent.agent_id
        assert isinstance(agent_id, AgentId)
        # Verify it's a valid hex string
        hex_str = agent_id.to_hex()
        assert len(hex_str) == 64  # SHA-256 of public key

    @pytest.mark.asyncio
    async def test_with_machine_key_custom_path(self):
        """Test agent creation with custom machine key path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, "custom_machine.key")

            # Build agent with custom path
            agent = await Agent.builder().with_machine_key(key_path).build()
            assert agent is not None

            # Verify the key file was created
            assert os.path.exists(key_path), "Machine key file should be created"

    @pytest.mark.asyncio
    async def test_with_machine_key_reuses_existing(self):
        """Test that using the same machine key path reuses the identity."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, "reuse_machine.key")

            # Create first agent
            agent1 = await Agent.builder().with_machine_key(key_path).build()
            machine_id1 = agent1.machine_id.to_hex()

            # Create second agent with same path
            agent2 = await Agent.builder().with_machine_key(key_path).build()
            machine_id2 = agent2.machine_id.to_hex()

            # Machine IDs should be identical
            assert machine_id1 == machine_id2, "Machine IDs should match when reusing key file"

    @pytest.mark.asyncio
    async def test_with_machine_key_invalid_path(self):
        """Test error handling for invalid machine key path."""
        # Use a path that can't be written to (directory doesn't exist)
        invalid_path = "/nonexistent/path/to/machine.key"

        with pytest.raises(Exception):  # Should raise IOError or similar
            await Agent.builder().with_machine_key(invalid_path).build()

    @pytest.mark.asyncio
    async def test_with_agent_key_import_export(self):
        """Test agent keypair export and import."""
        # Create an agent
        agent1 = await Agent.builder().build()
        agent_id1 = agent1.agent_id

        # Get keypair bytes (for now, we'll test with generated keys)
        # Note: In real usage, you'd export public_key and secret_key from the agent
        # For this test, we'll create a fresh keypair and test the import mechanism

        # This test verifies the signature is correct - actual export/import
        # will be implemented in a future task when we add keypair export methods
        pass  # Placeholder - will enhance when export methods added

    @pytest.mark.asyncio
    async def test_builder_consumed_error(self):
        """Test that builder can only be used once."""
        builder = Agent.builder()

        # First build should succeed
        agent1 = await builder.build()
        assert agent1 is not None

        # Second build on same builder should fail
        with pytest.raises(ValueError, match="Builder already consumed"):
            await builder.build()

    @pytest.mark.asyncio
    async def test_method_chaining(self):
        """Test that builder methods can be chained."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, "chain_test.key")

            # Chain multiple builder methods
            agent = await (
                Agent.builder()
                .with_machine_key(key_path)
                .build()
            )

            assert agent is not None
            assert os.path.exists(key_path)

    @pytest.mark.asyncio
    async def test_multiple_agents_different_identities(self):
        """Test that creating multiple agents generates different identities."""
        agent1 = await Agent.builder().build()
        agent2 = await Agent.builder().build()

        # Agent IDs should be different (different keypairs)
        assert agent1.agent_id.to_hex() != agent2.agent_id.to_hex()


class TestAgentClassMethod:
    """Test Agent class methods."""

    def test_builder_classmethod(self):
        """Test that Agent.builder() returns an AgentBuilder."""
        builder = Agent.builder()
        assert isinstance(builder, AgentBuilder)


# Run tests with: pytest tests/test_agent_builder.py -v
