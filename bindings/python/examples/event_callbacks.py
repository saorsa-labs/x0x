#!/usr/bin/env python3
"""
Event Callbacks Example

This example demonstrates:
- Registering event callbacks
- Handling different event types
- Removing callbacks

Note: Event dispatch will work when Phase 1.3 (Gossip Overlay Integration)
is complete. Currently this demonstrates the callback API.
"""

import asyncio
from x0x import Agent


class EventLogger:
    """Helper class to log events."""

    def __init__(self, name):
        self.name = name
        self.events = []

    def on_connected(self, event_data):
        """Handle connected event."""
        print(f"[{self.name}] Connected!")
        print(f"  Event data: {event_data}")
        self.events.append(("connected", event_data))

    def on_disconnected(self, event_data):
        """Handle disconnected event."""
        print(f"[{self.name}] Disconnected!")
        print(f"  Event data: {event_data}")
        self.events.append(("disconnected", event_data))

    def on_peer_joined(self, event_data):
        """Handle peer joined event."""
        print(f"[{self.name}] Peer joined!")
        print(f"  Peer ID: {event_data.get('peer_id', 'unknown')}")
        print(f"  Address: {event_data.get('address', 'unknown')}")
        self.events.append(("peer_joined", event_data))


async def main():
    print("=== x0x Event Callbacks Example ===\n")

    # Create agent
    agent = await Agent.builder().build()
    print("✓ Agent created\n")

    # Create event logger
    logger = EventLogger("Agent1")

    # Register event callbacks
    print("Registering event callbacks...")
    agent.on("connected", logger.on_connected)
    agent.on("disconnected", logger.on_disconnected)
    agent.on("peer_joined", logger.on_peer_joined)
    print("✓ Callbacks registered\n")

    # You can also use lambdas
    agent.on("task_updated", lambda data: print(f"Task updated: {data}"))

    # Join network (would trigger 'connected' event when Phase 1.3 is complete)
    print("Joining network...")
    await agent.join_network()
    print("✓ Network joined\n")

    # Simulate some activity
    print("Agent is active (events would fire here)...")
    await asyncio.sleep(1)

    # Remove a callback
    print("\nRemoving 'peer_joined' callback...")
    agent.off("peer_joined", logger.on_peer_joined)
    print("✓ Callback removed\n")

    # Leave network (would trigger 'disconnected' event when Phase 1.3 is complete)
    print("Leaving network...")
    await agent.leave_network()
    print("✓ Network left\n")

    # Show logged events
    print(f"Events logged: {len(logger.events)}")
    for event_type, event_data in logger.events:
        print(f"  - {event_type}: {event_data}")

    print("\n=== Example Complete ===")
    print("\nNote: Events will be dispatched when Phase 1.3")
    print("(Gossip Overlay Integration) is complete.")


if __name__ == "__main__":
    asyncio.run(main())
