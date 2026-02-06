#!/usr/bin/env python3
"""
Pub/Sub Messaging Example

This example demonstrates:
- Publishing messages to topics
- Subscribing to topics
- Receiving messages via async iteration

Note: Message delivery will work when Phase 1.3 (Gossip Overlay Integration)
is complete. Currently this demonstrates the API without actual network delivery.
"""

import asyncio
from x0x import Agent


async def publisher(agent, topic, message_count=5):
    """Publish messages to a topic."""
    print(f"\n[Publisher] Starting...")

    for i in range(message_count):
        payload = f"Message {i+1}".encode()
        await agent.publish(topic, payload)
        print(f"[Publisher] Published: {payload.decode()}")
        await asyncio.sleep(0.5)

    print("[Publisher] Done")


async def subscriber(agent, topic):
    """Subscribe to a topic and receive messages."""
    print(f"\n[Subscriber] Subscribing to '{topic}'...")

    subscription = agent.subscribe(topic)
    print(f"[Subscriber] Subscribed (topic: {subscription.topic})")

    # Note: With placeholder implementation, this won't yield messages
    # When Phase 1.3 is complete, messages will be received here
    message_count = 0
    async for msg in subscription:
        print(f"[Subscriber] Received: {msg.payload.decode()}")
        print(f"[Subscriber]   From: {msg.sender.to_hex()[:16]}...")
        print(f"[Subscriber]   Timestamp: {msg.timestamp}")
        message_count += 1

        if message_count >= 5:
            subscription.close()
            break

    print(f"[Subscriber] Received {message_count} messages")


async def main():
    print("=== x0x Pub/Sub Messaging Example ===")

    # Create two agents
    agent1 = await Agent.builder().build()
    agent2 = await Agent.builder().build()

    print("✓ Created two agents")

    # Join network
    await agent1.join_network()
    await agent2.join_network()

    print("✓ Both agents connected")

    # Topic to use
    topic = "announcements"

    # Run publisher and subscriber concurrently
    # Note: With placeholder implementation, subscriber won't receive messages
    # This will work when Phase 1.3 is complete
    await asyncio.gather(
        publisher(agent1, topic),
        subscriber(agent2, topic),
    )

    # Cleanup
    await agent1.leave_network()
    await agent2.leave_network()

    print("\n=== Example Complete ===")
    print("\nNote: Message delivery will work when Phase 1.3")
    print("(Gossip Overlay Integration) is complete.")


if __name__ == "__main__":
    asyncio.run(main())
