"""
Pytest configuration and fixtures for x0x Python bindings.
"""

import pytest
import pytest_asyncio

from x0x import Agent


@pytest_asyncio.fixture
async def agent():
    """Create a test agent and clean up after test.

    Returns:
        Agent: A configured agent instance
    """
    agent = await Agent.builder().build()
    yield agent
    # Cleanup: leave network if connected
    try:
        if agent.is_connected():
            await agent.leave_network()
    except Exception:
        pass  # Best effort cleanup


@pytest_asyncio.fixture
async def two_agents():
    """Create two agents for testing multi-agent scenarios.

    Returns:
        tuple[Agent, Agent]: Two configured agent instances
    """
    agent1 = await Agent.builder().build()
    agent2 = await Agent.builder().build()

    yield agent1, agent2

    # Cleanup
    for agent in [agent1, agent2]:
        try:
            if agent.is_connected():
                await agent.leave_network()
        except Exception:
            pass


@pytest.fixture
def event_tracker():
    """Create an event tracking helper for testing callbacks.

    Returns:
        EventTracker: Helper object for tracking events
    """

    class EventTracker:
        """Helper for tracking callback invocations in tests."""

        def __init__(self):
            self.events = []

        def callback(self, event_data):
            """Track event callback invocation."""
            self.events.append(event_data)

        def clear(self):
            """Clear tracked events."""
            self.events.clear()

        @property
        def count(self):
            """Number of events tracked."""
            return len(self.events)

        def get(self, index):
            """Get event at index."""
            return self.events[index] if index < len(self.events) else None

    return EventTracker()


@pytest.fixture
def sample_message_payload():
    """Sample message payload for testing.

    Returns:
        bytes: Test message payload
    """
    return b"Hello, x0x network!"


@pytest.fixture
def sample_topic():
    """Sample topic name for testing.

    Returns:
        str: Test topic name
    """
    return "test-topic"
