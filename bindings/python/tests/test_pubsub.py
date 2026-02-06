"""
Tests for Agent pub/sub functionality.
"""

import pytest
import pytest_asyncio

# Import x0x types
from x0x import Agent, Message, Subscription


class TestPublish:
    """Test message publishing functionality."""

    @pytest.mark.asyncio
    async def test_publish_basic(self):
        """Test basic message publishing."""
        agent = await Agent.builder().build()
        await agent.join_network()

        # Should be able to publish without error (placeholder implementation)
        await agent.publish("test-topic", b"Hello, world!")

    @pytest.mark.asyncio
    async def test_publish_empty_payload(self):
        """Test publishing empty payload."""
        agent = await Agent.builder().build()

        # Should accept empty payload
        await agent.publish("test-topic", b"")

    @pytest.mark.asyncio
    async def test_publish_large_payload(self):
        """Test publishing large payload."""
        agent = await Agent.builder().build()

        # Publish 1MB payload
        large_payload = b"x" * (1024 * 1024)
        await agent.publish("test-topic", large_payload)

    @pytest.mark.asyncio
    async def test_publish_multiple_topics(self):
        """Test publishing to multiple topics."""
        agent = await Agent.builder().build()

        await agent.publish("topic1", b"message1")
        await agent.publish("topic2", b"message2")
        await agent.publish("topic3", b"message3")

    @pytest.mark.asyncio
    async def test_publish_before_join(self):
        """Test that publish works even before explicit join_network call."""
        agent = await Agent.builder().build()

        # Should not error (network created during build)
        await agent.publish("test-topic", b"message")


class TestSubscribe:
    """Test subscription functionality."""

    @pytest.mark.asyncio
    async def test_subscribe_returns_subscription(self):
        """Test that subscribe returns a Subscription object."""
        agent = await Agent.builder().build()

        subscription = agent.subscribe("test-topic")

        assert isinstance(subscription, Subscription)
        assert subscription.topic == "test-topic"
        assert not subscription.closed

    @pytest.mark.asyncio
    async def test_subscription_is_async_iterable(self):
        """Test that Subscription can be used in async for."""
        agent = await Agent.builder().build()

        subscription = agent.subscribe("test-topic")

        # Should be able to use in async for (will immediately end with placeholder)
        message_count = 0
        async for msg in subscription:
            message_count += 1
            # Placeholder implementation returns None, so this won't execute
            break

        # Placeholder implementation yields no messages
        assert message_count == 0

    @pytest.mark.asyncio
    async def test_subscription_close(self):
        """Test closing a subscription."""
        agent = await Agent.builder().build()

        subscription = agent.subscribe("test-topic")
        assert not subscription.closed

        subscription.close()
        assert subscription.closed

    @pytest.mark.asyncio
    async def test_multiple_subscriptions_different_topics(self):
        """Test creating multiple subscriptions to different topics."""
        agent = await Agent.builder().build()

        sub1 = agent.subscribe("topic1")
        sub2 = agent.subscribe("topic2")
        sub3 = agent.subscribe("topic3")

        assert sub1.topic == "topic1"
        assert sub2.topic == "topic2"
        assert sub3.topic == "topic3"

    @pytest.mark.asyncio
    async def test_multiple_subscriptions_same_topic(self):
        """Test creating multiple subscriptions to the same topic."""
        agent = await Agent.builder().build()

        sub1 = agent.subscribe("same-topic")
        sub2 = agent.subscribe("same-topic")

        # Both should be valid subscriptions
        assert sub1.topic == "same-topic"
        assert sub2.topic == "same-topic"
        assert sub1 is not sub2  # Different objects


class TestMessage:
    """Test Message type functionality."""

    def test_message_has_payload(self):
        """Test that Message has payload attribute."""
        # We can't directly construct Message from Python (it's created by Rust)
        # So this is a placeholder for when we can test actual messages
        pass

    def test_message_has_sender(self):
        """Test that Message has sender attribute."""
        # Placeholder - will test when we can receive actual messages
        pass

    def test_message_has_timestamp(self):
        """Test that Message has timestamp attribute."""
        # Placeholder - will test when we can receive actual messages
        pass


class TestPubSubIntegration:
    """Test pub/sub integration (placeholder for future)."""

    @pytest.mark.asyncio
    async def test_publish_subscribe_roundtrip(self):
        """Test publishing and receiving a message (placeholder)."""
        agent = await Agent.builder().build()

        # Subscribe to topic
        subscription = agent.subscribe("test-topic")

        # Publish message
        await agent.publish("test-topic", b"test message")

        # Note: Current placeholder implementation won't deliver messages
        # When gossip integration is complete, this test should be updated to:
        # 1. Actually receive the message via async for
        # 2. Verify payload, sender, timestamp
        # 3. Test message deduplication

        # For now, just verify no errors
        message_count = 0
        async for msg in subscription:
            message_count += 1
            break

        # Placeholder yields no messages
        assert message_count == 0

    @pytest.mark.asyncio
    async def test_multiple_agents_pubsub(self):
        """Test pub/sub between multiple agents (placeholder)."""
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create two agents with different machine keys
            agent1 = await Agent.builder().with_machine_key(
                os.path.join(tmpdir, "agent1.key")
            ).build()

            agent2 = await Agent.builder().with_machine_key(
                os.path.join(tmpdir, "agent2.key")
            ).build()

            # Both subscribe to same topic
            sub1 = agent1.subscribe("shared-topic")
            sub2 = agent2.subscribe("shared-topic")

            # Agent1 publishes
            await agent1.publish("shared-topic", b"from agent1")

            # Agent2 publishes
            await agent2.publish("shared-topic", b"from agent2")

            # Note: Placeholder implementation won't deliver messages
            # This test documents expected behavior for future implementation


class TestSubscriptionBehavior:
    """Test Subscription object behavior and properties."""

    @pytest.mark.asyncio
    async def test_subscription_topic_property(self):
        """Test subscription.topic property."""
        agent = await Agent.builder().build()

        subscription = agent.subscribe("my-topic")

        assert hasattr(subscription, "topic")
        assert subscription.topic == "my-topic"

    @pytest.mark.asyncio
    async def test_subscription_closed_property(self):
        """Test subscription.closed property."""
        agent = await Agent.builder().build()

        subscription = agent.subscribe("my-topic")

        # Initially not closed
        assert hasattr(subscription, "closed")
        assert subscription.closed is False

        # After close
        subscription.close()
        assert subscription.closed is True

    @pytest.mark.asyncio
    async def test_subscription_close_idempotent(self):
        """Test that calling close() multiple times is safe."""
        agent = await Agent.builder().build()

        subscription = agent.subscribe("my-topic")

        subscription.close()
        subscription.close()
        subscription.close()

        assert subscription.closed is True


# Run tests with: pytest tests/test_pubsub.py -v
