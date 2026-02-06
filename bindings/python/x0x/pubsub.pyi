"""Type stubs for pub/sub message types."""

from typing import AsyncIterator

from .identity import AgentId

class Message:
    """A message received from the gossip network."""

    @property
    def payload(self) -> bytes:
        """The message payload as bytes."""
        ...

    @property
    def sender(self) -> AgentId:
        """The agent ID of the sender."""
        ...

    @property
    def timestamp(self) -> int:
        """Unix timestamp (seconds since epoch) when message was created."""
        ...

    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class Subscription(AsyncIterator[Message]):
    """Async iterator for receiving messages from a subscription."""

    @property
    def topic(self) -> str:
        """The topic this subscription is listening to."""
        ...

    @property
    def closed(self) -> bool:
        """Whether this subscription is closed."""
        ...

    def close(self) -> None:
        """Close the subscription and stop receiving messages."""
        ...

    def __aiter__(self) -> Subscription: ...
    async def __anext__(self) -> Message: ...
