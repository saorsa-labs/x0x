"""
Agent implementation for the x0x gossip network.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import AsyncIterator


@dataclass
class Message:
    """A message received from the gossip network."""

    origin: str
    """The originating agent's identifier."""

    payload: bytes
    """The message payload."""

    topic: str
    """The topic this message was published to."""


class Agent:
    """An agent in the x0x gossip network.

    Each agent is a peer — there is no client/server distinction.
    Agents discover each other through gossip and communicate
    via epidemic broadcast.
    """

    def __init__(self) -> None:
        self._connected = False

    async def join_network(self) -> None:
        """Join the x0x gossip network.

        Begins peer discovery and epidemic broadcast participation.
        """
        # Placeholder — will connect via ant-quic Python bindings
        self._connected = True

    async def subscribe(self, topic: str) -> AsyncIterator[Message]:
        """Subscribe to messages on a topic.

        Args:
            topic: The topic to subscribe to.

        Yields:
            Messages as they arrive through the gossip network.
        """
        # Placeholder — will use saorsa-gossip pubsub
        return
        yield  # Make this a generator

    async def publish(self, topic: str, payload: bytes) -> None:
        """Publish a message to a topic.

        The message propagates through the network via epidemic broadcast —
        every agent that receives it relays to its neighbours.

        Args:
            topic: The topic to publish to.
            payload: The message payload.
        """
        # Placeholder — will use saorsa-gossip pubsub
        pass
