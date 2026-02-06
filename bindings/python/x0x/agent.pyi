"""Type stubs for Agent and AgentBuilder."""

from typing import Awaitable, Callable, Optional, TypedDict

from .identity import AgentId, MachineId
from .pubsub import Subscription

class EventData(TypedDict, total=False):
    """Event data dictionary passed to callbacks.

    Fields vary by event type:
    - connected: peer_id
    - disconnected: peer_id
    - peer_joined: peer_id, address
    - task_updated: task_id, status, assignee
    """

    peer_id: str
    address: str
    task_id: str
    status: str
    assignee: Optional[str]

class Agent:
    """The core agent that participates in the x0x gossip network."""

    @classmethod
    def builder(cls) -> AgentBuilder:
        """Create an AgentBuilder for configuration."""
        ...

    @property
    def machine_id(self) -> MachineId:
        """Get the machine ID for this agent."""
        ...

    @property
    def agent_id(self) -> AgentId:
        """Get the agent ID for this agent."""
        ...

    async def join_network(self) -> None:
        """Join the x0x gossip network.

        Raises:
            IOError: If network join fails
        """
        ...

    async def leave_network(self) -> None:
        """Leave the x0x gossip network.

        Raises:
            IOError: If network leave fails
        """
        ...

    def is_connected(self) -> bool:
        """Check if agent is connected to the network."""
        ...

    def peer_id(self) -> str:
        """Get the peer ID (hex-encoded) for this agent."""
        ...

    async def publish(self, topic: str, payload: bytes) -> None:
        """Publish a message to a topic.

        Args:
            topic: Topic name
            payload: Message payload as bytes

        Raises:
            RuntimeError: If publish fails
        """
        ...

    def subscribe(self, topic: str) -> Subscription:
        """Subscribe to a topic to receive messages.

        Args:
            topic: Topic name to subscribe to

        Returns:
            Subscription object (async iterator)
        """
        ...

    def on(self, event: str, callback: Callable[[EventData], None]) -> None:
        """Register a callback for an event.

        Args:
            event: Event name (connected, disconnected, peer_joined, task_updated)
            callback: Callable that receives event data dict
        """
        ...

    def off(self, event: str, callback: Callable[[EventData], None]) -> None:
        """Remove a callback for an event.

        Args:
            event: Event name
            callback: Callable to remove
        """
        ...

class AgentBuilder:
    """Builder for creating Agent instances with custom configuration."""

    def with_machine_key(self, path: str) -> AgentBuilder:
        """Set custom machine key path.

        Args:
            path: Path to machine key file

        Returns:
            Self for chaining
        """
        ...

    def with_agent_key(self, keypair: bytes) -> AgentBuilder:
        """Import agent keypair from bytes.

        Args:
            keypair: Serialized keypair bytes

        Returns:
            Self for chaining
        """
        ...

    async def build(self) -> Agent:
        """Build the Agent with configured settings.

        Returns:
            Configured Agent instance

        Raises:
            IOError: If agent creation fails
        """
        ...
