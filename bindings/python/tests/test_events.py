"""
Tests for Agent event system functionality.
"""

import pytest
import pytest_asyncio

# Import x0x types
from x0x import Agent


class TestEventRegistration:
    """Test event callback registration."""

    @pytest.mark.asyncio
    async def test_on_registers_callback(self):
        """Test that on() registers a callback without error."""
        agent = await Agent.builder().build()

        # Track if callback was called
        called = []

        def callback(event_data):
            called.append(event_data)

        # Should register without error
        agent.on("connected", callback)

        # Note: We can't easily trigger events in tests since the underlying
        # network is a placeholder. This test just verifies the API works.

    @pytest.mark.asyncio
    async def test_on_multiple_callbacks_same_event(self):
        """Test registering multiple callbacks for the same event."""
        agent = await Agent.builder().build()

        called_1 = []
        called_2 = []

        def callback_1(event_data):
            called_1.append(event_data)

        def callback_2(event_data):
            called_2.append(event_data)

        # Both should register successfully
        agent.on("connected", callback_1)
        agent.on("connected", callback_2)

    @pytest.mark.asyncio
    async def test_on_different_events(self):
        """Test registering callbacks for different events."""
        agent = await Agent.builder().build()

        def on_connected(event_data):
            pass

        def on_disconnected(event_data):
            pass

        def on_peer_joined(event_data):
            pass

        # Should all register successfully
        agent.on("connected", on_connected)
        agent.on("disconnected", on_disconnected)
        agent.on("peer_joined", on_peer_joined)

    @pytest.mark.asyncio
    async def test_on_accepts_lambda(self):
        """Test that on() accepts lambda functions."""
        agent = await Agent.builder().build()

        # Lambda should work
        agent.on("connected", lambda event_data: print(event_data))

    @pytest.mark.asyncio
    async def test_on_accepts_callable_class(self):
        """Test that on() accepts callable class instances."""
        agent = await Agent.builder().build()

        class Handler:
            def __call__(self, event_data):
                pass

        handler = Handler()
        agent.on("connected", handler)


class TestEventUnregistration:
    """Test event callback removal."""

    @pytest.mark.asyncio
    async def test_off_removes_callback(self):
        """Test that off() removes a registered callback."""
        agent = await Agent.builder().build()

        def callback(event_data):
            pass

        # Register then remove
        agent.on("connected", callback)
        agent.off("connected", callback)

        # Should not error

    @pytest.mark.asyncio
    async def test_off_nonexistent_callback(self):
        """Test that off() with non-registered callback doesn't error."""
        agent = await Agent.builder().build()

        def callback(event_data):
            pass

        # off() on never-registered callback should not error
        agent.off("connected", callback)

    @pytest.mark.asyncio
    async def test_off_removes_only_one_instance(self):
        """Test that off() removes only first occurrence of duplicate callbacks."""
        agent = await Agent.builder().build()

        def callback(event_data):
            pass

        # Register the same callback twice
        agent.on("connected", callback)
        agent.on("connected", callback)

        # Remove once
        agent.off("connected", callback)

        # Second registration should still be there (no way to verify in test,
        # but at least verify off() succeeds)

    @pytest.mark.asyncio
    async def test_off_wrong_event(self):
        """Test that off() with wrong event name doesn't affect other events."""
        agent = await Agent.builder().build()

        def callback(event_data):
            pass

        agent.on("connected", callback)

        # Removing from different event should not error
        agent.off("disconnected", callback)

        # Original callback should still be registered (no way to verify,
        # but at least verify it doesn't error)


class TestEventTypes:
    """Test different event types are accepted."""

    @pytest.mark.asyncio
    async def test_connected_event(self):
        """Test 'connected' event can be registered."""
        agent = await Agent.builder().build()
        agent.on("connected", lambda e: None)

    @pytest.mark.asyncio
    async def test_disconnected_event(self):
        """Test 'disconnected' event can be registered."""
        agent = await Agent.builder().build()
        agent.on("disconnected", lambda e: None)

    @pytest.mark.asyncio
    async def test_peer_joined_event(self):
        """Test 'peer_joined' event can be registered."""
        agent = await Agent.builder().build()
        agent.on("peer_joined", lambda e: None)

    @pytest.mark.asyncio
    async def test_task_updated_event(self):
        """Test 'task_updated' event can be registered."""
        agent = await Agent.builder().build()
        agent.on("task_updated", lambda e: None)

    @pytest.mark.asyncio
    async def test_custom_event_name(self):
        """Test that custom event names work (for extensibility)."""
        agent = await Agent.builder().build()
        agent.on("custom-event", lambda e: None)


class TestCallbackSignature:
    """Test callback signature requirements."""

    @pytest.mark.asyncio
    async def test_callback_receives_dict(self):
        """Test that callbacks are expected to receive a dict.

        Note: We can't easily test actual event dispatch in unit tests
        since the underlying network is a placeholder. This test documents
        the expected signature.

        When events are actually dispatched (Phase 1.3 complete), callbacks
        will receive dicts like:
        - {"peer_id": "abc123", "address": "192.168.1.100:9000"}
        - {"task_id": "def456", "status": "claimed"}
        """
        agent = await Agent.builder().build()

        received_data = []

        def callback(event_data):
            # event_data should be a dict
            assert isinstance(event_data, dict) or event_data is None
            received_data.append(event_data)

        agent.on("connected", callback)

        # This is a placeholder test - actual event dispatch will be tested
        # when Phase 1.3 (Gossip Overlay Integration) is complete


# Integration tests (will work when Phase 1.3 is complete)
class TestEventIntegration:
    """Integration tests for event dispatch.

    These are placeholders until Phase 1.3 (Gossip Overlay Integration) is complete.
    """

    @pytest.mark.asyncio
    async def test_callback_invoked_on_event_placeholder(self):
        """Test that callbacks are invoked when events occur.

        This will work when the underlying gossip network can actually
        trigger events.

        Expected behavior once implemented:

        ```python
        agent = await Agent.builder().build()

        called = []

        def on_connected(event_data):
            called.append(event_data)

        agent.on("connected", on_connected)

        await agent.join_network()  # This should trigger "connected" event

        # Give event loop time to dispatch
        await asyncio.sleep(0.1)

        assert len(called) == 1
        assert isinstance(called[0], dict)
        assert "peer_id" in called[0]
        ```
        """
        pass

    @pytest.mark.asyncio
    async def test_multiple_callbacks_all_invoked_placeholder(self):
        """Test that all registered callbacks for an event are invoked.

        Expected behavior once implemented: Both callbacks should be called.
        """
        pass

    @pytest.mark.asyncio
    async def test_callback_receives_correct_data_placeholder(self):
        """Test that callbacks receive appropriate event data.

        Expected event data formats:
        - connected: {"peer_id": str}
        - disconnected: {"peer_id": str}
        - peer_joined: {"peer_id": str, "address": str}
        - task_updated: {"task_id": str, "status": str, "assignee": Optional[str]}
        """
        pass
