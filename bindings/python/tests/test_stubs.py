"""
Tests for type stub functionality.
"""

import sys
from pathlib import Path


class TestStubImports:
    """Test that type stubs can be imported."""

    def test_stub_files_exist(self):
        """Test that all expected stub files exist."""
        stub_dir = Path(__file__).parent.parent / "x0x"

        expected_stubs = [
            "__init__.pyi",
            "agent.pyi",
            "identity.pyi",
            "pubsub.pyi",
            "task_list.pyi",
        ]

        for stub_file in expected_stubs:
            stub_path = stub_dir / stub_file
            assert stub_path.exists(), f"Stub file missing: {stub_path}"

    def test_stub_syntax_valid(self):
        """Test that stub files have valid Python syntax."""
        stub_dir = Path(__file__).parent.parent / "x0x"
        stub_files = list(stub_dir.glob("*.pyi"))

        assert len(stub_files) > 0, "No stub files found"

        for stub_file in stub_files:
            content = stub_file.read_text()
            # Should compile without syntax errors
            compile(content, str(stub_file), "exec")

    def test_main_module_exports_in_stub(self):
        """Test that __init__.pyi exports match actual module."""
        stub_file = Path(__file__).parent.parent / "x0x" / "__init__.pyi"
        content = stub_file.read_text()

        # Check that key exports are mentioned
        expected_exports = [
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

        for export in expected_exports:
            assert export in content, f"Export {export} not found in __init__.pyi"

    def test_agent_stub_has_methods(self):
        """Test that agent.pyi declares expected methods."""
        stub_file = Path(__file__).parent.parent / "x0x" / "agent.pyi"
        content = stub_file.read_text()

        expected_methods = [
            "builder",
            "join_network",
            "leave_network",
            "is_connected",
            "publish",
            "subscribe",
            "on",
            "off",
        ]

        for method in expected_methods:
            assert method in content, f"Method {method} not found in agent.pyi"

    def test_task_list_stub_has_methods(self):
        """Test that task_list.pyi declares expected methods."""
        stub_file = Path(__file__).parent.parent / "x0x" / "task_list.pyi"
        content = stub_file.read_text()

        expected_methods = [
            "add_task",
            "claim_task",
            "complete_task",
            "list_tasks",
            "reorder",
        ]

        for method in expected_methods:
            assert method in content, f"Method {method} not found in task_list.pyi"

    def test_task_status_literal_defined(self):
        """Test that TaskStatus literal type is defined."""
        stub_file = Path(__file__).parent.parent / "x0x" / "task_list.pyi"
        content = stub_file.read_text()

        # Should have TaskStatus = Literal["empty", "claimed", "done"]
        assert "TaskStatus" in content
        assert "Literal" in content
        assert "empty" in content
        assert "claimed" in content
        assert "done" in content

    def test_event_data_typed_dict_defined(self):
        """Test that EventData TypedDict is defined in agent stubs."""
        stub_file = Path(__file__).parent.parent / "x0x" / "agent.pyi"
        content = stub_file.read_text()

        # Should have EventData TypedDict
        assert "EventData" in content
        assert "TypedDict" in content

    def test_async_methods_marked(self):
        """Test that async methods are properly marked in stubs."""
        stub_file = Path(__file__).parent.parent / "x0x" / "agent.pyi"
        content = stub_file.read_text()

        # Async methods should have "async def"
        assert "async def join_network" in content
        assert "async def leave_network" in content
        assert "async def publish" in content

    def test_async_iterator_for_subscription(self):
        """Test that Subscription is typed as AsyncIterator."""
        stub_file = Path(__file__).parent.parent / "x0x" / "pubsub.pyi"
        content = stub_file.read_text()

        # Subscription should be AsyncIterator[Message]
        assert "AsyncIterator" in content
        assert "Message" in content
        assert "__aiter__" in content
        assert "__anext__" in content
