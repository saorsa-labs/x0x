#!/usr/bin/env python3
"""
Basic x0x Agent Example

This example demonstrates:
- Creating an agent
- Retrieving agent identities
- Joining and leaving the network
"""

import asyncio
from x0x import Agent


async def main():
    print("=== x0x Basic Agent Example ===\n")

    # Create an agent
    print("Creating agent...")
    agent = await Agent.builder().build()
    print("✓ Agent created\n")

    # Get agent identities
    machine_id = agent.machine_id
    agent_id = agent.agent_id
    peer_id = agent.peer_id()

    print("Agent Identities:")
    print(f"  Machine ID: {machine_id.to_hex()[:16]}...")
    print(f"  Agent ID:   {agent_id.to_hex()[:16]}...")
    print(f"  Peer ID:    {peer_id[:16]}...\n")

    # Join the network
    print("Joining network...")
    await agent.join_network()
    print(f"✓ Connected: {agent.is_connected()}\n")

    # Leave the network
    print("Leaving network...")
    await agent.leave_network()
    print("✓ Disconnected\n")

    print("=== Example Complete ===")


if __name__ == "__main__":
    asyncio.run(main())
