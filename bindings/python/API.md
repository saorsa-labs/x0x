# x0x Python API Reference

Complete API documentation for x0x Python bindings.

## Table of Contents

- [Agent](#agent)
- [AgentBuilder](#agentbuilder)
- [Identity Types](#identity-types)
- [Pub/Sub](#pubsub)
- [Task Lists](#task-lists)
- [Events](#events)

---

## Agent

The core agent that participates in the x0x gossip network.

### Creating an Agent

```python
from x0x import Agent

# Using builder pattern (recommended)
agent = await Agent.builder().build()

# With custom machine key
agent = await Agent.builder().with_machine_key("/path/to/key").build()
```

### Properties

#### `machine_id` → `MachineId`

Get the machine ID for this agent. The machine ID is tied to this computer and used for QUIC transport authentication.

```python
machine_id = agent.machine_id
print(machine_id.to_hex())  # 64-character hex string
```

#### `agent_id` → `AgentId`

Get the agent ID. The agent ID is portable across machines and represents the agent's persistent identity.

```python
agent_id = agent.agent_id
print(agent_id.to_hex())  # 64-character hex string
```

### Methods

#### `await join_network()`

Join the x0x gossip network. Begins peer discovery and epidemic broadcast.

**Raises:** `IOError` if network join fails

```python
await agent.join_network()
```

#### `await leave_network()`

Leave the x0x gossip network.

**Raises:** `IOError` if network leave fails

```python
await agent.leave_network()
```

#### `is_connected()` → `bool`

Check if agent is connected to the network.

```python
if agent.is_connected():
    print("Connected!")
```

#### `peer_id()` → `str`

Get the peer ID (hex-encoded) for this agent.

```python
peer_id = agent.peer_id()
```

#### `await publish(topic: str, payload: bytes)`

Publish a message to a topic.

**Args:**
- `topic`: Topic name
- `payload`: Message payload as bytes

**Raises:** `RuntimeError` if publish fails

```python
await agent.publish("announcements", b"Hello, network!")
```

#### `subscribe(topic: str)` → `Subscription`

Subscribe to a topic to receive messages.

**Args:**
- `topic`: Topic name to subscribe to

**Returns:** `Subscription` object (async iterator)

```python
subscription = agent.subscribe("announcements")
async for msg in subscription:
    print(f"Received: {msg.payload.decode()}")
```

#### `on(event: str, callback: Callable[[dict], None])`

Register a callback for an event.

**Args:**
- `event`: Event name (connected, disconnected, peer_joined, task_updated)
- `callback`: Callable that receives event data dict

```python
def on_connected(event_data):
    print(f"Connected! Peer: {event_data.get('peer_id')}")

agent.on("connected", on_connected)
```

#### `off(event: str, callback: Callable[[dict], None])`

Remove a callback for an event.

**Args:**
- `event`: Event name
- `callback`: Callable to remove

```python
agent.off("connected", on_connected)
```

---

## AgentBuilder

Builder for creating Agent instances with custom configuration.

### Methods

#### `with_machine_key(path: str)` → `AgentBuilder`

Set custom machine key path.

**Args:**
- `path`: Path to machine key file

**Returns:** Self for chaining

```python
builder = Agent.builder().with_machine_key("~/.x0x/custom_machine.key")
```

#### `with_agent_key(keypair: bytes)` → `AgentBuilder`

Import agent keypair from bytes.

**Args:**
- `keypair`: Serialized keypair bytes

**Returns:** Self for chaining

```python
builder = Agent.builder().with_agent_key(keypair_bytes)
```

#### `await build()` → `Agent`

Build the Agent with configured settings.

**Returns:** Configured Agent instance

**Raises:** `IOError` if agent creation fails

```python
agent = await Agent.builder().build()
```

---

## Identity Types

### MachineId

Machine identity - tied to this computer for QUIC transport.

#### Class Methods

##### `from_hex(hex_str: str)` → `MachineId`

Create MachineId from hex string.

**Args:**
- `hex_str`: 64-character hex string (32 bytes)

**Raises:** `ValueError` if hex string is invalid or wrong length

```python
machine_id = MachineId.from_hex("a" * 64)
```

#### Instance Methods

##### `to_hex()` → `str`

Convert to hex-encoded string.

**Returns:** 64-character hex string

```python
hex_str = machine_id.to_hex()
```

### AgentId

Agent identity - portable across machines.

#### Class Methods

##### `from_hex(hex_str: str)` → `AgentId`

Create AgentId from hex string.

**Args:**
- `hex_str`: 64-character hex string (32 bytes)

**Raises:** `ValueError` if hex string is invalid or wrong length

```python
agent_id = AgentId.from_hex("b" * 64)
```

#### Instance Methods

##### `to_hex()` → `str`

Convert to hex-encoded string.

**Returns:** 64-character hex string

```python
hex_str = agent_id.to_hex()
```

---

## Pub/Sub

### Message

A message received from the gossip network.

#### Properties

##### `payload` → `bytes`

The message payload as bytes.

```python
data = msg.payload
text = data.decode()  # If text
```

##### `sender` → `AgentId`

The agent ID of the sender.

```python
sender_id = msg.sender.to_hex()
```

##### `timestamp` → `int`

Unix timestamp (seconds since epoch) when message was created.

```python
import datetime
dt = datetime.datetime.fromtimestamp(msg.timestamp)
```

### Subscription

Async iterator for receiving messages from a subscription.

#### Properties

##### `topic` → `str`

The topic this subscription is listening to.

```python
print(f"Subscribed to: {subscription.topic}")
```

##### `closed` → `bool`

Whether this subscription is closed.

```python
if subscription.closed:
    print("Subscription closed")
```

#### Methods

##### `close()`

Close the subscription and stop receiving messages.

```python
subscription.close()
```

#### Async Iterator

Use `async for` to receive messages:

```python
subscription = agent.subscribe("my-topic")
async for msg in subscription:
    print(f"Received: {msg.payload}")
    if some_condition:
        subscription.close()
        break
```

---

## Task Lists

### TaskId

A unique identifier for a task in a task list.

#### Class Methods

##### `from_hex(hex_str: str)` → `TaskId`

Create TaskId from hex string.

**Args:**
- `hex_str`: 64-character hex string (32 bytes)

**Raises:** `ValueError` if hex string is invalid or wrong length

```python
task_id = TaskId.from_hex("c" * 64)
```

#### Instance Methods

##### `to_hex()` → `str`

Convert to hex-encoded string.

**Returns:** 64-character hex string

```python
hex_str = task_id.to_hex()
```

### TaskItem

A snapshot of a task's current state.

#### Properties

##### `id` → `str`

Task ID (hex-encoded).

##### `title` → `str`

Task title.

##### `description` → `str`

Task description.

##### `status` → `Literal["empty", "claimed", "done"]`

Checkbox state:
- `"empty"`: Available to be claimed
- `"claimed"`: Assigned to an agent
- `"done"`: Completed

##### `assignee` → `Optional[str]`

Agent ID of assignee (hex-encoded) if claimed or done.

##### `priority` → `int`

Display priority (0-255, higher = more important).

### TaskList

A handle to a collaborative task list with CRDT synchronization.

#### Methods

##### `await add_task(title: str, description: Optional[str] = None)` → `str`

Add a new task to the list.

**Args:**
- `title`: Task title
- `description`: Optional detailed description

**Returns:** Task ID as hex-encoded string

**Raises:** `RuntimeError` if operation fails

```python
task_id = await task_list.add_task("Fix bug", "Network timeout issue")
```

##### `await claim_task(task_id: str)`

Claim a task for the current agent.

**Args:**
- `task_id`: ID of task to claim (hex string)

**Raises:**
- `ValueError` if task_id is invalid hex
- `RuntimeError` if operation fails

```python
await task_list.claim_task(task_id)
```

##### `await complete_task(task_id: str)`

Mark a task as complete.

**Args:**
- `task_id`: ID of task to complete (hex string)

**Raises:**
- `ValueError` if task_id is invalid hex
- `RuntimeError` if operation fails

```python
await task_list.complete_task(task_id)
```

##### `await list_tasks()` → `list[TaskItem]`

Get a snapshot of all tasks in the list.

**Returns:** List of TaskItem objects

**Raises:** `RuntimeError` if operation fails

```python
tasks = await task_list.list_tasks()
for task in tasks:
    print(f"[{task.status}] {task.title}")
```

##### `await reorder(task_ids: list[str])`

Reorder tasks in the list.

**Args:**
- `task_ids`: List of task IDs in desired order (hex strings)

**Raises:**
- `ValueError` if any task_id is invalid hex
- `RuntimeError` if operation fails

```python
await task_list.reorder([task_id1, task_id2, task_id3])
```

---

## Events

The event system allows you to register callbacks for network and task events.

### Event Types

| Event | Description | Event Data |
|-------|-------------|------------|
| `connected` | Agent connected to network | `{"peer_id": str}` |
| `disconnected` | Agent disconnected from network | `{"peer_id": str}` |
| `peer_joined` | New peer discovered | `{"peer_id": str, "address": str}` |
| `task_updated` | Task state changed | `{"task_id": str, "status": str, "assignee": Optional[str]}` |

### Example

```python
def on_peer_joined(event_data):
    peer_id = event_data.get("peer_id")
    address = event_data.get("address")
    print(f"New peer: {peer_id} at {address}")

agent.on("peer_joined", on_peer_joined)
```

---

## Type Hints

All public APIs include type stubs (`.pyi` files) for IDE autocomplete and type checking. Use `mypy` for static type checking:

```bash
pip install mypy
mypy your_script.py
```

---

## Examples

See the [examples](examples/) directory for complete working examples:

- `basic_agent.py` - Agent creation and network operations
- `pubsub_messaging.py` - Publish/subscribe messaging
- `event_callbacks.py` - Event handling with callbacks

---

## Support

For issues or questions:
- GitHub: https://github.com/saorsa-labs/x0x
- Email: david@saorsalabs.com
