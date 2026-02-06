# Phase 2.2: Python Bindings (PyO3) - Implementation Plan

**Phase**: 2.2
**Name**: Python Bindings (PyO3)
**Status**: Planning Complete
**Created**: 2026-02-06
**Estimated Tasks**: 10

---

## Overview

Build a complete Python SDK for x0x using PyO3, exposing the Rust core library to Python applications with async-native APIs. This phase creates platform-specific wheels using maturin, type stubs for IDE support, and a Pythonic async API for network operations.

The bindings will expose:
- Agent identity creation and management (async)
- Network joining and peer discovery (async)
- Pub/sub messaging with async iterators
- Collaborative task lists with CRDT synchronization
- Full type hints via .pyi stub files

**Key Differences from Node.js Bindings:**
- Package name: `agent-x0x` on PyPI (x0x was taken)
- Import as: `from x0x import Agent, TaskList`
- Async-native using Python's asyncio
- Snake_case naming (Python conventions)
- Type stubs (.pyi) instead of auto-generated types

---

## Dependencies

- **Phase 1.1** (Agent Identity) - COMPLETE
- **Phase 1.2** (Network Transport) - COMPLETE
- **Phase 1.5** (MLS Group Encryption) - COMPLETE
- **Phase 2.1** (napi-rs Node.js Bindings) - COMPLETE (reference implementation)

---

## Task Breakdown

### Task 1: Initialize PyO3 Project Structure with Maturin
**Files**:
- `bindings/python/Cargo.toml`
- `bindings/python/pyproject.toml`
- `bindings/python/README.md`
- `bindings/python/.gitignore`
- `Cargo.toml` (workspace root - add python bindings)

Initialize maturin project with PyO3 dependencies and proper Python packaging configuration.

**Requirements:**
- Add PyO3 dependencies: `pyo3 = { version = "0.23", features = ["extension-module", "abi3-py38"] }`
- Configure `[lib]` with `crate-type = ["cdylib"]` in Cargo.toml
- Set up pyproject.toml with maturin build backend
- Package name: `agent-x0x`, import name: `x0x`
- Configure for abi3 (stable Python ABI) targeting Python 3.8+
- Add python bindings to workspace in root Cargo.toml
- Basic README with installation instructions

**Tests**: Verify `maturin develop` builds successfully and `python -c "import x0x"` works.

---

### Task 2: Identity Bindings - MachineId, AgentId, PublicKey
**Files**:
- `bindings/python/src/lib.rs`
- `bindings/python/src/identity.rs`
- `bindings/python/tests/test_identity.py`

Expose x0x identity types to Python with proper conversions and string representations.

**Requirements:**
- `#[pyclass]` wrappers for `MachineId`, `AgentId`, `PublicKey`
- `__str__()` and `__repr__()` returning hex-encoded strings
- `@classmethod` `from_hex(cls, hex_str: str)` for deserialization
- `to_hex()` method returning string
- `__hash__()` and `__eq__()` for dict/set usage
- Export from lib.rs using `#[pymodule]` macro

**Tests** (pytest):
- Create identity, convert to hex string, parse back
- Test equality and hashing
- Test invalid hex string raises ValueError

---

### Task 3: Agent Builder Pattern Bindings
**Files**:
- `bindings/python/src/agent.rs`
- `bindings/python/tests/test_agent_builder.py`

Expose `Agent` creation with builder pattern for configuration.

**Requirements:**
- `#[pyclass]` wrapper for `Agent` and `AgentBuilder`
- `Agent.builder()` class method returning `AgentBuilder`
- `AgentBuilder.with_machine_key(path: str)` - chainable
- `AgentBuilder.with_agent_key(keypair: bytes)` - chainable
- `async def AgentBuilder.build() -> Agent` - creates agent asynchronously
- Handle Rust Result types by raising Python exceptions (ValueError, IOError)
- Proper __del__ for cleanup

**Tests** (pytest-asyncio):
- `agent = await Agent.builder().build()`
- Builder with custom machine key path
- Test error when invalid path provided

---

### Task 4: Async Network Operations - Join, Leave
**Files**:
- `bindings/python/src/agent.rs` (update)
- `bindings/python/tests/test_network.py`

Expose async network operations using pyo3-asyncio for tokio integration.

**Requirements:**
- Add `pyo3-asyncio = { version = "0.23", features = ["tokio-runtime"] }`
- `async def agent.join_network() -> None` - awaitable
- `async def agent.leave_network() -> None` - awaitable
- `agent.is_connected() -> bool` - sync check
- `agent.peer_id() -> str` - returns hex PeerId
- Proper integration with Python's asyncio event loop
- Use `#[pyo3(signature = (...))]` for async methods

**Tests** (pytest-asyncio):
- Create agent, join network (mock), verify is_connected()
- Test peer_id() returns valid hex string
- Test leave_network() cleanup

---

### Task 5: Pub/Sub Bindings with Async Iterators
**Files**:
- `bindings/python/src/pubsub.rs`
- `bindings/python/src/agent.rs` (update)
- `bindings/python/tests/test_pubsub.py`

Expose publish/subscribe with Python async iterators for receiving messages.

**Requirements:**
- `async def agent.publish(topic: str, payload: bytes) -> None`
- `agent.subscribe(topic: str) -> AsyncIterator[Message]` - returns async iterator
- `#[pyclass]` for `Message` with `payload: bytes`, `sender: AgentId`, `timestamp: int`
- Use `__aiter__()` and `__anext__()` for async iteration
- Proper cancellation handling when iterator dropped
- Message deduplication on Rust side

**Tests** (pytest-asyncio):
- Subscribe to topic, publish message, receive via `async for`
- Test unsubscribe/cancellation
- Test multiple subscribers to same topic

---

### Task 6: TaskList CRDT Bindings
**Files**:
- `bindings/python/src/task_list.rs`
- `bindings/python/tests/test_task_list.py`

Expose CRDT-based TaskList with Pythonic API for task management.

**Requirements:**
- `#[pyclass]` for `TaskList`, `TaskItem`, `TaskId`
- `async def TaskList.create(name: str) -> TaskList`
- `async def task_list.add_task(title: str, description: str = "") -> TaskId`
- `async def task_list.claim_task(task_id: TaskId, agent_id: AgentId) -> None`
- `async def task_list.complete_task(task_id: TaskId) -> None`
- `task_list.get_tasks() -> list[TaskItem]` - sync snapshot
- `TaskItem` with properties: `id`, `title`, `description`, `status`, `assignee`
- `status` enum: `Empty`, `Claimed`, `Done`

**Tests** (pytest-asyncio):
- Create task list, add task, claim, complete
- Test concurrent claims (OR-Set semantics)
- Test get_tasks() returns current state

---

### Task 7: Event System with Callbacks
**Files**:
- `bindings/python/src/events.rs`
- `bindings/python/src/agent.rs` (update)
- `bindings/python/tests/test_events.py`

Expose event system for connection events, task updates, etc.

**Requirements:**
- `agent.on(event: str, callback: Callable) -> None` - register callback
- `agent.off(event: str, callback: Callable) -> None` - unregister
- Events: `"connected"`, `"disconnected"`, `"peer_joined"`, `"task_updated"`
- Callbacks receive event-specific Python dict
- Use `py.allow_threads()` to avoid GIL issues
- Store callbacks as `PyObject` references

**Tests** (pytest-asyncio):
- Register callback, trigger event (mock), verify called
- Test multiple callbacks for same event
- Test off() removes callback

---

### Task 8: Type Stubs (.pyi) Generation
**Files**:
- `bindings/python/x0x/__init__.pyi`
- `bindings/python/x0x/agent.pyi`
- `bindings/python/x0x/task_list.pyi`
- `bindings/python/generate_stubs.py`

Create type stub files for IDE autocomplete and type checking.

**Requirements:**
- Stub for all public classes: `Agent`, `AgentBuilder`, `TaskList`, `TaskItem`, `Message`
- Async method signatures with proper return types
- TypedDict for event callback payloads
- Enum for TaskStatus: `Empty`, `Claimed`, `Done`
- Generic types where applicable (AsyncIterator[Message])
- Script to validate stubs against runtime (using mypy)

**Tests**:
- Run `mypy` on test files with stubs
- Verify IDE autocomplete works (manual check)
- Test stub imports: `from x0x import Agent`

---

### Task 9: Integration Tests with pytest
**Files**:
- `bindings/python/tests/conftest.py`
- `bindings/python/tests/test_integration.py`
- `bindings/python/pytest.ini`

Comprehensive integration tests using pytest and pytest-asyncio.

**Requirements:**
- Pytest fixtures for agent creation, cleanup
- Test full workflow: create agent → join → subscribe → publish → receive
- Test task list: create → add → claim → complete → sync
- Test concurrent operations (multiple agents)
- Test error handling and edge cases
- Mock network where appropriate (avoid real network calls in tests)
- Coverage reporting with pytest-cov

**Tests**:
- End-to-end messaging test
- End-to-end task collaboration test
- Error handling tests (network failure, invalid input)

---

### Task 10: Examples and Documentation
**Files**:
- `bindings/python/examples/basic_agent.py`
- `bindings/python/examples/task_collaboration.py`
- `bindings/python/examples/pubsub_messaging.py`
- `bindings/python/README.md` (update)
- `bindings/python/API.md`

Create runnable examples and comprehensive documentation.

**Requirements:**
- Example 1: Basic agent creation and network join
- Example 2: Pub/sub messaging between two agents
- Example 3: Task list collaboration (add, claim, complete)
- Example 4: Event handling and callbacks
- README with:
  - Installation: `pip install agent-x0x`
  - Quick start code snippet
  - Link to examples and API docs
- API.md with class/method reference (auto-generated from docstrings)
- Docstrings on all public Python classes/methods

**Tests**:
- Verify all examples run without errors: `python examples/basic_agent.py`
- Docstring coverage check (>=90%)

---

## Success Criteria

- ✅ All tasks completed (10/10)
- ✅ Zero compilation errors or warnings
- ✅ All pytest tests passing (aim for >90% coverage)
- ✅ Type stubs pass mypy validation
- ✅ Examples run successfully
- ✅ Documentation complete and accurate
- ✅ `maturin build --release` produces wheels for target platforms
- ✅ Package installs cleanly: `pip install dist/*.whl`
- ✅ Import works: `python -c "from x0x import Agent"`

---

## Notes

- **Blocked Dependencies**: Tasks 4-7 depend on Phase 1.3 (Gossip Overlay) for real network functionality. Can implement with mock/placeholder until Phase 1.3 complete.
- **Python Version**: Target Python 3.8+ using abi3 for forward compatibility
- **Async Runtime**: Use pyo3-asyncio with tokio runtime for Rust-Python async bridge
- **Platform Wheels**: Defer CI/CD wheel building to Phase 2.3 - this phase focuses on source distribution and local development
- **PyPI Package Name**: `agent-x0x` (x0x was taken) but imports as `from x0x import ...`

---

## Reference Implementation

Phase 2.1 (Node.js bindings) serves as the reference API. Python bindings should mirror the same functionality with Pythonic naming and async conventions.

**Node.js API** → **Python API**:
- `Agent.create()` → `Agent.builder().build()`
- `agent.joinNetwork()` → `await agent.join_network()`
- `agent.subscribe(topic, callback)` → `async for msg in agent.subscribe(topic)`
- `taskList.addTask(title)` → `await task_list.add_task(title)`
