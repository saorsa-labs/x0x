"""
Integration tests for x0x Python bindings.

These tests cover end-to-end workflows across multiple components.
Note: Many tests use placeholder implementations that will become
functional when Phase 1.3 (Gossip Overlay Integration) is complete.
"""

import pytest
import pytest_asyncio

from x0x import Agent


class TestAgentLifecycle:
    """Test complete agent lifecycle workflows."""

    @pytest.mark.asyncio
    async def test_agent_creation_and_properties(self, agent):
        """Test agent can be created and has expected properties."""
        # Agent should be created successfully by fixture
        assert agent is not None

        # Should have identity properties
        machine_id = agent.machine_id
        agent_id = agent.agent_id

        assert machine_id is not None
        assert agent_id is not None

        # IDs should be hex strings when converted
        assert len(machine_id.to_hex()) == 64
        assert len(agent_id.to_hex()) == 64

    @pytest.mark.asyncio
    async def test_agent_join_leave_network(self, agent):
        """Test agent can join and leave network."""
        # Should not be connected initially
        # (Note: placeholder implementation may vary)

        # Should be able to join
        await agent.join_network()

        # Should be able to leave
        await agent.leave_network()

    @pytest.mark.asyncio
    async def test_agent_peer_id(self, agent):
        """Test agent has a peer ID."""
        peer_id = agent.peer_id()

        # Should be a hex string
        assert isinstance(peer_id, str)
        assert len(peer_id) == 64  # 32 bytes hex-encoded


class TestPubSubWorkflow:
    """Test publish/subscribe workflows."""

    @pytest.mark.asyncio
    async def test_subscribe_and_publish(self, agent, sample_topic, sample_message_payload):
        """Test basic pub/sub workflow.

        Note: Actual message delivery will work when Phase 1.3 is complete.
        This test verifies the API works without errors.
        """
        # Subscribe to topic
        subscription = agent.subscribe(sample_topic)
        assert subscription is not None
        assert subscription.topic == sample_topic

        # Publish message
        await agent.publish(sample_topic, sample_message_payload)

        # Note: With placeholder implementation, subscription won't yield messages
        # When Phase 1.3 is complete, we would receive the message here

    @pytest.mark.asyncio
    async def test_multiple_subscriptions(self, agent):
        """Test agent can subscribe to multiple topics."""
        topics = ["topic1", "topic2", "topic3"]

        subscriptions = []
        for topic in topics:
            sub = agent.subscribe(topic)
            subscriptions.append(sub)

        # All subscriptions should be valid
        assert len(subscriptions) == 3
        for sub, topic in zip(subscriptions, topics):
            assert sub.topic == topic

    @pytest.mark.asyncio
    async def test_subscription_lifecycle(self, agent, sample_topic):
        """Test subscription can be created and closed."""
        subscription = agent.subscribe(sample_topic)

        # Should not be closed initially
        assert not subscription.closed

        # Should be able to close
        subscription.close()
        assert subscription.closed


class TestMultiAgentScenarios:
    """Test scenarios with multiple agents."""

    @pytest.mark.asyncio
    async def test_two_agents_have_identities(self, two_agents):
        """Test that two agents have valid identities.

        Note: Agents created from the same builder will share the same
        identity (machine and agent IDs), which is correct behavior.
        The peer ID is derived from the agent ID.
        """
        agent1, agent2 = two_agents

        # Both should have valid machine IDs
        assert agent1.machine_id is not None
        assert agent2.machine_id is not None
        assert len(agent1.machine_id.to_hex()) == 64
        assert len(agent2.machine_id.to_hex()) == 64

        # Both should have valid agent IDs
        assert agent1.agent_id is not None
        assert agent2.agent_id is not None
        assert len(agent1.agent_id.to_hex()) == 64
        assert len(agent2.agent_id.to_hex()) == 64

        # Both should have valid peer IDs
        assert agent1.peer_id() is not None
        assert agent2.peer_id() is not None
        assert len(agent1.peer_id()) == 64
        assert len(agent2.peer_id()) == 64

    @pytest.mark.asyncio
    async def test_two_agents_can_join_network(self, two_agents):
        """Test multiple agents can join network.

        When Phase 1.3 is complete, this will test actual peer discovery.
        """
        agent1, agent2 = two_agents

        # Both should be able to join
        await agent1.join_network()
        await agent2.join_network()

        # Both should be able to leave
        await agent1.leave_network()
        await agent2.leave_network()


class TestEventSystemIntegration:
    """Test event system integration."""

    @pytest.mark.asyncio
    async def test_register_callbacks_for_multiple_events(self, agent, event_tracker):
        """Test callbacks can be registered for multiple event types."""
        events = ["connected", "disconnected", "peer_joined", "task_updated"]

        for event in events:
            agent.on(event, event_tracker.callback)

        # Should register without error
        # When Phase 1.3 is complete, events will actually fire

    @pytest.mark.asyncio
    async def test_callback_registration_and_removal(self, agent, event_tracker):
        """Test complete callback lifecycle."""

        def callback1(data):
            event_tracker.events.append(("callback1", data))

        def callback2(data):
            event_tracker.events.append(("callback2", data))

        # Register both callbacks
        agent.on("connected", callback1)
        agent.on("connected", callback2)

        # Remove callback1
        agent.off("connected", callback1)

        # callback2 should still be registered
        # (No way to verify in placeholder implementation)


class TestErrorHandling:
    """Test error handling in integration scenarios."""

    @pytest.mark.asyncio
    async def test_invalid_topic_name_handling(self, agent):
        """Test that invalid input is handled gracefully."""
        # Should handle empty topic
        await agent.publish("", b"test")

        # Should handle special characters
        await agent.publish("topic/with/slashes", b"test")

    @pytest.mark.asyncio
    async def test_empty_payload_handling(self, agent, sample_topic):
        """Test empty payloads are handled correctly."""
        # Should accept empty payload
        await agent.publish(sample_topic, b"")

    @pytest.mark.asyncio
    async def test_large_payload_handling(self, agent, sample_topic):
        """Test large payloads are handled correctly."""
        # Create 1MB payload
        large_payload = b"x" * (1024 * 1024)

        # Should handle without error
        await agent.publish(sample_topic, large_payload)


class TestConcurrentOperations:
    """Test concurrent operations."""

    @pytest.mark.asyncio
    async def test_concurrent_publishes(self, agent, sample_topic):
        """Test multiple concurrent publishes."""
        import asyncio

        # Publish 10 messages concurrently
        tasks = [
            agent.publish(sample_topic, f"message-{i}".encode()) for i in range(10)
        ]

        # Should all complete without error
        await asyncio.gather(*tasks)

    @pytest.mark.asyncio
    async def test_concurrent_agent_creation(self):
        """Test creating multiple agents concurrently.

        Note: Agents created from the same default builder will share
        the same identity. This test verifies concurrent creation works,
        not that IDs are unique (which requires custom builders).
        """
        import asyncio

        # Create 5 agents concurrently
        async def create_agent():
            return await Agent.builder().build()

        agents = await asyncio.gather(*[create_agent() for _ in range(5)])

        # All should be created successfully
        assert len(agents) == 5

        # All should have valid peer IDs
        peer_ids = [agent.peer_id() for agent in agents]
        assert len(peer_ids) == 5
        assert all(len(pid) == 64 for pid in peer_ids)  # All valid hex strings


# Placeholder for future tests when Phase 1.3 is complete
class TestRealNetworkOperations:
    """Integration tests for real network operations.

    These tests are placeholders and will become functional when
    Phase 1.3 (Gossip Overlay Integration) is complete.
    """

    @pytest.mark.asyncio
    async def test_message_delivery_placeholder(self):
        """Test actual message delivery between agents.

        Expected behavior once Phase 1.3 is complete:

        ```python
        agent1 = await Agent.builder().build()
        agent2 = await Agent.builder().build()

        await agent1.join_network()
        await agent2.join_network()

        # Give network time to discover peers
        await asyncio.sleep(1)

        received = []

        def on_message(msg):
            received.append(msg)

        # Subscribe on agent2
        subscription = agent2.subscribe("test-topic")

        # Publish from agent1
        await agent1.publish("test-topic", b"Hello!")

        # Receive on agent2
        async for msg in subscription:
            received.append(msg)
            break

        assert len(received) == 1
        assert received[0].payload == b"Hello!"
        ```
        """
        pass

    @pytest.mark.asyncio
    async def test_task_list_synchronization_placeholder(self):
        """Test task list CRDT synchronization between agents.

        Expected behavior once Phase 1.4 is complete:

        ```python
        agent1 = await Agent.builder().build()
        agent2 = await Agent.builder().build()

        # Both create/join same task list
        task_list1 = await agent1.create_task_list("shared-tasks")
        task_list2 = await agent2.join_task_list("shared-tasks")

        # Agent1 adds task
        task_id = await task_list1.add_task("Test task", "Description")

        # Give CRDT time to sync
        await asyncio.sleep(0.5)

        # Agent2 should see the task
        tasks = await task_list2.list_tasks()
        assert len(tasks) == 1
        assert tasks[0].id == task_id
        ```
        """
        pass
