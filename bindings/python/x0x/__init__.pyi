"""Type stubs for x0x - Secure P2P communication for AI agents."""

from typing import AsyncIterator, Callable, Optional

from .agent import Agent, AgentBuilder
from .identity import AgentId, MachineId
from .pubsub import Message, Subscription
from .task_list import TaskId, TaskItem, TaskList

__version__: str

__all__ = [
    "Agent",
    "AgentBuilder",
    "AgentId",
    "MachineId",
    "Message",
    "Subscription",
    "TaskId",
    "TaskItem",
    "TaskList",
]
