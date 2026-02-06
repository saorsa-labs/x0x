# x0x Python Bindings

Python bindings for x0x - A post-quantum secure P2P communication network for AI agents.

## Installation

### From PyPI (when published)
```bash
pip install agent-x0x
```

### From Source
```bash
# Install maturin
pip install maturin

# Build and install in development mode
cd bindings/python
maturin develop

# Or build wheel
maturin build --release
pip install target/wheels/*.whl
```

## Quick Start

```python
from x0x import Agent
import asyncio

async def main():
    # Create an agent
    agent = await Agent.builder().build()

    # Join the network
    await agent.join_network()

    # Subscribe to a topic
    async for message in agent.subscribe("my-topic"):
        print(f"Received: {message.payload}")

    # Publish a message
    await agent.publish("my-topic", b"Hello, world!")

    # Clean up
    await agent.leave_network()

if __name__ == "__main__":
    asyncio.run(main())
```

## Features

- **Post-Quantum Cryptography**: ML-KEM-768 key exchange, ML-DSA-65 signatures
- **NAT Traversal**: Built-in QUIC hole punching, no STUN/TURN required
- **CRDT Task Lists**: Collaborative task management with automatic conflict resolution
- **Async-Native**: Full asyncio integration for Python applications
- **Type Safe**: Complete type stubs for IDE autocomplete and type checking

## Documentation

See the [examples](examples/) directory for complete usage examples:
- `basic_agent.py` - Agent creation and network joining
- `pubsub_messaging.py` - Publish/subscribe messaging between agents
- `task_collaboration.py` - Collaborative task management with CRDTs
- `event_callbacks.py` - Event handling with callbacks

For API reference, see [API.md](API.md).

**Note**: Package name on PyPI is `agent-x0x` (because `x0x` was taken), but you import it as `from x0x import Agent`.

## Requirements

- Python 3.8+
- Works on Linux (x86_64, aarch64), macOS (x86_64, arm64), Windows (x86_64)

## License

Dual-licensed under AGPL-3.0-or-later OR Commercial. See [LICENSE](../../LICENSE) for details.

## Support

- GitHub Issues: https://github.com/saorsa-labs/x0x/issues
- Email: david@saorsalabs.com
