"""Type stubs for identity types."""

from typing import Any

class MachineId:
    """Machine identity - tied to this computer for QUIC transport."""

    @classmethod
    def from_hex(cls, hex_str: str) -> MachineId:
        """Create MachineId from hex string.

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

class AgentId:
    """Agent identity - portable across machines."""

    @classmethod
    def from_hex(cls, hex_str: str) -> AgentId:
        """Create AgentId from hex string.

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
