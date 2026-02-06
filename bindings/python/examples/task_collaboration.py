#!/usr/bin/env python3
"""
Task Collaboration Example

This example demonstrates:
- Two agents collaborating on a shared task list
- Agent 1 creates tasks
- Agent 2 discovers and claims tasks
- CRDT synchronization keeps both agents in sync
- Task lifecycle: Empty → Claimed → Done

Note: Full CRDT sync will work when Phase 1.3 (Gossip Overlay Integration)
is complete. Currently this demonstrates the API structure.
"""

import asyncio
from x0x import Agent


async def task_creator(agent, task_list, task_count=3):
    """Agent that creates tasks in the list."""
    print("\n[Creator] Starting task creation...")

    for i in range(task_count):
        title = f"Task {i+1}"
        description = f"Description for task {i+1}"

        # Note: create_task_list and add_task methods are defined in the
        # Rust core but not yet exposed in Python bindings (Phase 2.2 Task 6)
        # This example shows the intended API
        try:
            task_id = await task_list.add_task(title, description)
            print(f"[Creator] Created task: {title} (ID: {task_id[:16]}...)")
        except Exception as e:
            print(f"[Creator] Note: add_task not yet fully implemented: {e}")
            # When Phase 1.3 is complete, this will work
            break

        await asyncio.sleep(0.3)

    print("[Creator] Finished creating tasks")


async def task_worker(agent, task_list):
    """Agent that claims and completes tasks."""
    print("\n[Worker] Starting task processing...")

    # Give creator time to add tasks
    await asyncio.sleep(0.5)

    try:
        # List all available tasks
        tasks = await task_list.list_tasks()
        print(f"[Worker] Found {len(tasks)} tasks")

        for task in tasks:
            if task.status == "empty":
                # Claim the task
                print(f"[Worker] Claiming: {task.title}")
                await task_list.claim_task(task.id)

                # Simulate doing work
                await asyncio.sleep(0.5)

                # Mark as complete
                print(f"[Worker] Completing: {task.title}")
                await task_list.complete_task(task.id)
    except Exception as e:
        print(f"[Worker] Note: TaskList methods not fully implemented yet: {e}")
        # When Phase 1.3 is complete, this will work

    print("[Worker] Finished processing tasks")


async def show_final_state(task_list):
    """Display the final state of the task list."""
    print("\n=== Final Task List State ===")

    try:
        tasks = await task_list.list_tasks()

        for task in tasks:
            status_symbol = {
                "empty": "[ ]",
                "claimed": "[-]",
                "done": "[x]"
            }.get(task.status, "[?]")

            print(f"{status_symbol} {task.title}")
            if task.assignee:
                print(f"    Assigned to: {task.assignee[:16]}...")
    except Exception as e:
        print(f"Note: TaskList not fully implemented yet: {e}")
        print("This example will work when Phase 1.3 (Gossip Overlay) is complete.")


async def main():
    print("=== x0x Task Collaboration Example ===")
    print("\nThis example shows two agents collaborating on a shared task list.")
    print("Agent 1 creates tasks, Agent 2 claims and completes them.")
    print("The CRDT ensures both agents see consistent state.\n")

    # Create two agents
    agent1 = await Agent.builder().build()
    agent2 = await Agent.builder().build()

    print(f"✓ Created Agent 1 (ID: {agent1.agent_id.to_hex()[:16]}...)")
    print(f"✓ Created Agent 2 (ID: {agent2.agent_id.to_hex()[:16]}...)")

    # Join network
    await agent1.join_network()
    await agent2.join_network()

    print("✓ Both agents connected to network")

    # Note: create_task_list() method needs to be exposed in Python bindings
    # This is defined in Rust core but not yet in bindings/python/src/agent.rs
    try:
        # Agent 1 creates a task list
        task_list_name = "team-tasks"
        print(f"\n[Agent 1] Creating task list: {task_list_name}")
        task_list1 = await agent1.create_task_list(task_list_name)

        # Agent 2 joins the same task list
        print(f"[Agent 2] Joining task list: {task_list_name}")
        task_list2 = await agent2.join_task_list(task_list_name)

        print("✓ Both agents connected to task list")

        # Run creator and worker concurrently
        await asyncio.gather(
            task_creator(agent1, task_list1, task_count=5),
            task_worker(agent2, task_list2),
        )

        # Show final state (both agents should see same state due to CRDT)
        await show_final_state(task_list1)

    except AttributeError as e:
        print(f"\nNote: {e}")
        print("\nThe create_task_list() and join_task_list() methods exist in the")
        print("Rust core (src/lib.rs) but are not yet exposed in Python bindings.")
        print("This example demonstrates the intended API for task collaboration.")
        print("\nTo complete Phase 2.2, these methods should be added to:")
        print("  bindings/python/src/agent.rs")
        print("\nExample:")
        print("  async fn create_task_list(name: str) -> TaskList")
        print("  async fn join_task_list(name: str) -> TaskList")

    # Cleanup
    await agent1.leave_network()
    await agent2.leave_network()

    print("\n=== Example Complete ===")
    print("\nWhat this example demonstrates:")
    print("• CRDT-based task synchronization")
    print("• Three task states: Empty, Claimed, Done")
    print("• Collaborative workflow between multiple agents")
    print("• Eventual consistency through gossip protocol")


if __name__ == "__main__":
    asyncio.run(main())
