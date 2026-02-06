"""Type stubs for TaskList CRDT types."""

from typing import Any, Literal, Optional

TaskStatus = Literal["empty", "claimed", "done"]

class TaskId:
    """A unique identifier for a task in a task list."""

    @classmethod
    def from_hex(cls, hex_str: str) -> TaskId:
        """Create TaskId from hex string.

        Args:
            hex_str: 64-character hex string (32 bytes)

        Raises:
            ValueError: If hex string is invalid or wrong length
        """
        ...

    def to_hex(self) -> str:
        """Convert to hex-encoded string.

        Returns:
            64-character hex string
        """
        ...

    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: Any) -> bool: ...

class TaskItem:
    """A snapshot of a task's current state."""

    @property
    def id(self) -> str:
        """Task ID (hex-encoded)."""
        ...

    @property
    def title(self) -> str:
        """Task title."""
        ...

    @property
    def description(self) -> str:
        """Task description."""
        ...

    @property
    def status(self) -> TaskStatus:
        """Checkbox state: empty, claimed, or done."""
        ...

    @property
    def assignee(self) -> Optional[str]:
        """Agent ID of assignee (hex-encoded) if claimed or done."""
        ...

    @property
    def priority(self) -> int:
        """Display priority (0-255, higher = more important)."""
        ...

    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class TaskList:
    """A handle to a collaborative task list with CRDT synchronization."""

    async def add_task(self, title: str, description: Optional[str] = None) -> str:
        """Add a new task to the list.

        Args:
            title: Task title
            description: Optional detailed description

        Returns:
            Task ID as hex-encoded string

        Raises:
            RuntimeError: If operation fails
        """
        ...

    async def claim_task(self, task_id: str) -> None:
        """Claim a task for the current agent.

        Args:
            task_id: ID of task to claim (hex string)

        Raises:
            ValueError: If task_id is invalid hex
            RuntimeError: If operation fails
        """
        ...

    async def complete_task(self, task_id: str) -> None:
        """Mark a task as complete.

        Args:
            task_id: ID of task to complete (hex string)

        Raises:
            ValueError: If task_id is invalid hex
            RuntimeError: If operation fails
        """
        ...

    async def list_tasks(self) -> list[TaskItem]:
        """Get a snapshot of all tasks in the list.

        Returns:
            List of TaskItem objects

        Raises:
            RuntimeError: If operation fails
        """
        ...

    async def reorder(self, task_ids: list[str]) -> None:
        """Reorder tasks in the list.

        Args:
            task_ids: List of task IDs in desired order (hex strings)

        Raises:
            ValueError: If any task_id is invalid hex
            RuntimeError: If operation fails
        """
        ...
