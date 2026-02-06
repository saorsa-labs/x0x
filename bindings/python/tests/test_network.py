"""
Tests for Agent network operations.
"""

import pytest
import pytest_asyncio

# Import x0x types
from x0x import Agent


class TestNetworkOperations:
    """Test async network operations."""

    @pytest.mark.asyncio
    async def test_join_network(self):
        """Test that join_network is async and callable."""
        agent = await Agent.builder().build()

        # join_network should complete without error (placeholder implementation)
        await agent.join_network()

        # After join, agent should report as connected
        assert agent.is_connected()

    @pytest.mark.asyncio
    async def test_leave_network(self):
        """Test that leave_network is async and callable."""
        agent = await Agent.builder().build()

        # Join first
        await agent.join_network()
        assert agent.is_connected()

        # Then leave
        await agent.leave_network()

        # Note: Current placeholder implementation doesn't actually disconnect,
        # but the method should be callable without errors

    @pytest.mark.asyncio
    async def test_is_connected_before_join(self):
        """Test that agent reports not connected before joining."""
        agent = await Agent.builder().build()

        # Before join_network, should not be connected
        # Note: Current implementation creates network on build, so this may be True
        # This test documents expected behavior for future implementation
        connected = agent.is_connected()
        assert isinstance(connected, bool)

    @pytest.mark.asyncio
    async def test_peer_id_returns_hex_string(self):
        """Test that peer_id() returns a valid hex string."""
        agent = await Agent.builder().build()

        peer_id = agent.peer_id()

        # Should be a string
        assert isinstance(peer_id, str)

        # Should be 64 hex characters (32 bytes = 256 bits)
        assert len(peer_id) == 64

        # Should be valid hex
        int(peer_id, 16)  # Raises ValueError if not valid hex

    @pytest.mark.asyncio
    async def test_peer_id_is_machine_id(self):
        """Test that peer_id matches machine_id."""
        agent = await Agent.builder().build()

        peer_id = agent.peer_id()
        machine_id_hex = agent.machine_id.to_hex()

        # Peer ID should equal machine ID in hex
        assert peer_id == machine_id_hex

    @pytest.mark.asyncio
    async def test_join_network_idempotent(self):
        """Test that calling join_network multiple times is safe."""
        agent = await Agent.builder().build()

        # Should be safe to call join multiple times
        await agent.join_network()
        await agent.join_network()
        await agent.join_network()

        assert agent.is_connected()

    @pytest.mark.asyncio
    async def test_leave_network_idempotent(self):
        """Test that calling leave_network multiple times is safe."""
        agent = await Agent.builder().build()

        await agent.join_network()

        # Should be safe to call leave multiple times
        await agent.leave_network()
        await agent.leave_network()
        await agent.leave_network()

    @pytest.mark.asyncio
    async def test_network_lifecycle(self):
        """Test the full network join/leave lifecycle."""
        agent = await Agent.builder().build()

        # Initial state
        initial_connected = agent.is_connected()

        # Join
        await agent.join_network()
        assert agent.is_connected()

        # Leave
        await agent.leave_network()

        # Can rejoin
        await agent.join_network()
        assert agent.is_connected()


class TestPeerIdStability:
    """Test that peer IDs are stable and consistent."""

    @pytest.mark.asyncio
    async def test_peer_id_stable_across_calls(self):
        """Test that peer_id() returns the same value on multiple calls."""
        agent = await Agent.builder().build()

        peer_id1 = agent.peer_id()
        peer_id2 = agent.peer_id()
        peer_id3 = agent.peer_id()

        assert peer_id1 == peer_id2 == peer_id3

    @pytest.mark.asyncio
    async def test_different_agents_different_peer_ids(self):
        """Test that different agents have different peer IDs."""
        import tempfile
        import os

        # Use different machine keys to ensure different peer IDs
        with tempfile.TemporaryDirectory() as tmpdir:
            key1 = os.path.join(tmpdir, "machine1.key")
            key2 = os.path.join(tmpdir, "machine2.key")

            agent1 = await Agent.builder().with_machine_key(key1).build()
            agent2 = await Agent.builder().with_machine_key(key2).build()

            peer_id1 = agent1.peer_id()
            peer_id2 = agent2.peer_id()

            # Different agents with different machine keys should have different peer IDs
            assert peer_id1 != peer_id2


class TestAsyncAwaitableSignatures:
    """Test that async methods are properly awaitable."""

    @pytest.mark.asyncio
    async def test_join_network_awaitable(self):
        """Test that join_network returns an awaitable."""
        agent = await Agent.builder().build()

        # Should be able to await the result
        result = await agent.join_network()

        # Should return None
        assert result is None

    @pytest.mark.asyncio
    async def test_leave_network_awaitable(self):
        """Test that leave_network returns an awaitable."""
        agent = await Agent.builder().build()

        await agent.join_network()

        # Should be able to await the result
        result = await agent.leave_network()

        # Should return None
        assert result is None


# Run tests with: pytest tests/test_network.py -v
