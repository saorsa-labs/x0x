"""Tests for x0x identity types (MachineId, AgentId)."""

import pytest
from x0x import AgentId, MachineId


def test_machine_id_hex_roundtrip():
    """Test creating MachineId from hex and converting back."""
    hex_str = "a" * 64  # 32 bytes
    mid = MachineId.from_hex(hex_str)
    assert mid.to_hex() == hex_str


def test_agent_id_hex_roundtrip():
    """Test creating AgentId from hex and converting back."""
    hex_str = "b" * 64  # 32 bytes
    aid = AgentId.from_hex(hex_str)
    assert aid.to_hex() == hex_str


def test_machine_id_equality():
    """Test MachineId equality comparison."""
    hex_str = "c" * 64
    mid1 = MachineId.from_hex(hex_str)
    mid2 = MachineId.from_hex(hex_str)
    assert mid1 == mid2


def test_agent_id_equality():
    """Test AgentId equality comparison."""
    hex_str = "d" * 64
    aid1 = AgentId.from_hex(hex_str)
    aid2 = AgentId.from_hex(hex_str)
    assert aid1 == aid2


def test_machine_id_inequality():
    """Test MachineId inequality."""
    mid1 = MachineId.from_hex("a" * 64)
    mid2 = MachineId.from_hex("b" * 64)
    assert mid1 != mid2


def test_agent_id_inequality():
    """Test AgentId inequality."""
    aid1 = AgentId.from_hex("a" * 64)
    aid2 = AgentId.from_hex("b" * 64)
    assert aid1 != aid2


def test_machine_id_hash():
    """Test MachineId is hashable for use in dicts/sets."""
    hex_str = "e" * 64
    mid = MachineId.from_hex(hex_str)
    d = {mid: "value"}
    assert d[mid] == "value"

    # Test in set
    s = {mid}
    assert mid in s


def test_agent_id_hash():
    """Test AgentId is hashable for use in dicts/sets."""
    hex_str = "f" * 64
    aid = AgentId.from_hex(hex_str)
    d = {aid: "value"}
    assert d[aid] == "value"

    # Test in set
    s = {aid}
    assert aid in s


def test_machine_id_invalid_hex():
    """Test MachineId.from_hex raises ValueError for invalid hex."""
    with pytest.raises(ValueError, match="Invalid hex encoding"):
        MachineId.from_hex("not_valid_hex")


def test_agent_id_invalid_hex():
    """Test AgentId.from_hex raises ValueError for invalid hex."""
    with pytest.raises(ValueError, match="Invalid hex encoding"):
        AgentId.from_hex("zzz")


def test_machine_id_wrong_length():
    """Test MachineId.from_hex raises ValueError for wrong length."""
    with pytest.raises(ValueError, match="must be 32 bytes"):
        MachineId.from_hex("aa" * 16)  # Only 16 bytes


def test_agent_id_wrong_length():
    """Test AgentId.from_hex raises ValueError for wrong length."""
    with pytest.raises(ValueError, match="must be 32 bytes"):
        AgentId.from_hex("bb" * 20)  # Only 20 bytes


def test_machine_id_str():
    """Test MachineId __str__ returns full hex."""
    hex_str = "0123456789abcdef" * 4  # 32 bytes
    mid = MachineId.from_hex(hex_str)
    assert str(mid) == hex_str


def test_agent_id_str():
    """Test AgentId __str__ returns full hex."""
    hex_str = "fedcba9876543210" * 4  # 32 bytes
    aid = AgentId.from_hex(hex_str)
    assert str(aid) == hex_str


def test_machine_id_repr():
    """Test MachineId __repr__ includes type and abbreviated hex."""
    hex_str = "a" * 64
    mid = MachineId.from_hex(hex_str)
    repr_str = repr(mid)
    assert "MachineId" in repr_str
    assert "aaaaaaaaaaaaaaaa" in repr_str  # First 8 bytes


def test_agent_id_repr():
    """Test AgentId __repr__ includes type and abbreviated hex."""
    hex_str = "b" * 64
    aid = AgentId.from_hex(hex_str)
    repr_str = repr(aid)
    assert "AgentId" in repr_str
    assert "bbbbbbbbbbbbbbbb" in repr_str  # First 8 bytes


def test_machine_id_from_hex_case_insensitive():
    """Test MachineId.from_hex handles uppercase hex."""
    hex_lower = "abcdef01" * 8
    hex_upper = "ABCDEF01" * 8
    mid_lower = MachineId.from_hex(hex_lower)
    mid_upper = MachineId.from_hex(hex_upper)
    # Should be equal (hex decode is case-insensitive)
    assert mid_lower == mid_upper


def test_agent_id_from_hex_case_insensitive():
    """Test AgentId.from_hex handles uppercase hex."""
    hex_lower = "123abc" * 10 + "1234"  # 32 bytes
    hex_upper = hex_lower.upper()
    aid_lower = AgentId.from_hex(hex_lower)
    aid_upper = AgentId.from_hex(hex_upper)
    assert aid_lower == aid_upper
