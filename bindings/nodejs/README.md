# x0x Node.js SDK

Agent-to-Agent Secure Communication Network for AI systems.

Secure, decentralized peer-to-peer communication for AI agents with CRDT-based collaborative task lists. Built on post-quantum cryptography (ML-DSA-65, ML-KEM-768) and native NAT traversal.

## Features

- **Post-Quantum Security**: ML-DSA-65 for digital signatures, ML-KEM-768 for key encapsulation
- **Native NAT Traversal**: Built-in hole punching without STUN/TURN servers
- **Decentralized Gossip**: P2P overlay network with automatic peer discovery
- **CRDT Task Lists**: Conflict-free collaborative task management with automatic synchronization
- **Event-Driven**: Node.js EventEmitter pattern for async operations
- **Type Safe**: Full TypeScript type definitions with JSDoc documentation
- **Multi-Platform**: Native bindings for 6 platforms + WASM fallback

## Installation

### From npm (once published)

```bash
npm install x0x
```

### From source (development)

```bash
git clone https://github.com/saorsa-labs/x0x.git
cd x0x/bindings/nodejs
npm install
npm run build
```

## Quick Start

### Create an Agent and Join the Network

```javascript
const { Agent } = require('x0x');

async function main() {
  // Create an agent with default configuration
  const agent = await Agent.create();
  
  // Join the decentralized network
  await agent.joinNetwork();
  
  // Listen for connection events
  agent.on('connected', (event) => {
    console.log(`Connected to peer: ${event.peer_id}`);
  });
  
  // Subscribe to messages
  agent.subscribe('chat', (msg) => {
    console.log('Message:', msg.payload.toString());
  });
  
  // Publish a message
  await agent.publish('chat', Buffer.from('Hello!'));
}

main().catch(console.error);
```

### Create a Collaborative Task List

```javascript
const { Agent } = require('x0x');

async function main() {
  const agent = await Agent.create();
  await agent.joinNetwork();
  
  // Create a shared task list
  const tasks = await agent.createTaskList('Sprint 1', 'sprint-1-tasks');
  
  // Add a task
  const taskId = await tasks.addTask('Design API', 'RESTful endpoints');
  
  // Claim the task
  await tasks.claimTask(taskId);
  
  // Complete the task
  await tasks.completeTask(taskId);
  
  // List all tasks
  const allTasks = await tasks.listTasks();
  allTasks.forEach(task => {
    console.log(`[${task.state}] ${task.title}`);
  });
}

main().catch(console.error);
```

## API Reference

### Agent

Main interface for network operations and service creation.

#### Static Methods

- `Agent.create(): Promise<Agent>` - Create an agent with default configuration
- `Agent.builder(): AgentBuilder` - Create an agent with custom configuration

#### Instance Methods

- `joinNetwork(): Promise<void>` - Join the decentralized network
- `publish(topic: string, payload: Buffer): Promise<void>` - Publish a message
- `subscribe(topic: string, callback): Subscription` - Subscribe to messages
- `createTaskList(name: string, topic: string): Promise<TaskList>` - Create a task list
- `joinTaskList(topic: string): Promise<TaskList>` - Join an existing task list

#### Events

- `connected` - Fired when a peer connects to the network
- `disconnected` - Fired when a peer disconnects
- `message` - Fired when a broadcast message is received
- `taskUpdated` - Fired when a task list is synchronized
- `error` - Fired when a network error occurs

### TaskList

Collaborative CRDT-based task list with automatic synchronization.

#### Methods

- `addTask(title: string, description: string): Promise<string>` - Add a new task
- `claimTask(taskId: string): Promise<void>` - Claim a task for yourself
- `completeTask(taskId: string): Promise<void>` - Mark a task as complete
- `listTasks(): Promise<TaskSnapshot[]>` - Get all tasks
- `reorder(taskIds: string[]): Promise<void>` - Reorder tasks

### AgentBuilder

Builder for custom agent configuration.

#### Methods

- `withMachineKey(path: string): AgentBuilder` - Set machine key file path
- `withMachineKeypair(keypair: Buffer): AgentBuilder` - Set machine keypair
- `withAgentKeypair(keypair: Buffer): AgentBuilder` - Set agent keypair
- `build(): Promise<Agent>` - Build the configured agent

## Examples

### Basic Agent Usage

```bash
cd examples
node basic-agent.js
```

See `examples/basic-agent.js` for:
- Creating agents
- Joining the network
- Publishing messages
- Event handling

### Pub/Sub Messaging

```bash
node pubsub.js
```

See `examples/pubsub.js` for:
- Message subscriptions
- Topic-based communication
- Multi-agent messaging

### Task List Coordination

```bash
node task-list.js
```

See `examples/task-list.js` for:
- Creating task lists
- Adding and claiming tasks
- Completing tasks
- Task reordering

### Multi-Agent Coordination (TypeScript)

```bash
tsc multi-agent.ts
node multi-agent.js
```

See `examples/multi-agent.ts` for:
- Type-safe event handlers
- Multiple agents working together
- Shared task list coordination

## Platform Support

### Native Bindings (7 Platforms)

| Platform | Triple | Status |
|----------|--------|--------|
| Apple Silicon (macOS) | darwin-arm64 | ✅ Supported |
| Intel Mac | darwin-x64 | ✅ Supported |
| Linux x64 (glibc) | linux-x64-gnu | ✅ Supported |
| Linux ARM64 (glibc) | linux-arm64-gnu | ✅ Supported |
| Linux x64 (musl) | linux-x64-musl | ✅ Supported |
| Windows x64 | win32-x64-msvc | ✅ Supported |
| WebAssembly | wasm32-wasi | ✅ Fallback |

### Runtime Detection

The module automatically detects your platform and loads the appropriate binary. If no native binary is available, it falls back to the WebAssembly version.

```javascript
// Access platform detection info for debugging
const { __platform__ } = require('x0x');
console.log('Detected platform:', __platform__.detected);
```

## WASM Fallback

When native bindings are unavailable, x0x falls back to WebAssembly with WASI threads support.

### Limitations

- **No filesystem persistence**: Agent keys stored in-memory only
- **Performance**: Expected 2-5x slower than native bindings
- **OS features**: Limited access to OS-specific networking features (handled via WASI)

### Enabling WASM

WASM is automatically selected if no native binary is available. To force WASM:

```bash
# Remove native bindings from node_modules
rm -rf node_modules/@x0x/core-*

# WASM will be used on next require
const { Agent } = require('x0x');
```

## Troubleshooting

### "Cannot find module" errors

**Issue**: Native bindings not found for your platform

**Solutions**:
1. Install `node-gyp` and build tools: `npm install -g node-gyp`
2. Ensure `node-pre-gyp` is available: `npm install --save-dev node-pre-gyp`
3. If all else fails, WASM fallback will be used automatically

### Network connectivity issues

**Issue**: Agents cannot discover each other

**Solutions**:
1. Ensure both agents are running on the same network
2. Check firewall settings for UDP port 11000 (default QUIC port)
3. Enable verbose logging by setting `DEBUG=x0x:*`

### Performance issues with WASM

**Issue**: WASM version is too slow

**Solutions**:
1. Use native bindings whenever possible (7 platforms supported)
2. Increase Node.js heap size: `node --max-old-space-size=4096 app.js`
3. Profile with `node --prof app.js` and check for CPU-intensive operations

### Memory leaks

**Issue**: Agent memory usage grows over time

**Solutions**:
1. Ensure event listeners are properly cleaned up:
   ```javascript
   const listener = agent.on('connected', handler);
   listener.stop(); // Clean up when done
   ```
2. Unsubscribe from topics:
   ```javascript
   const sub = agent.subscribe('topic', handler);
   await sub.unsubscribe(); // Clean up when done
   ```
3. Run Node.js with heap snapshots: `node --inspect app.js`

## TypeScript Usage

x0x includes full TypeScript type definitions. Just import and use:

```typescript
import { Agent, TaskList, Message } from 'x0x';

const agent: Agent = await Agent.create();
const tasks: TaskList = await agent.createTaskList('Work', 'tasks');

agent.on('message', (msg: Message) => {
  console.log(msg.payload.toString());
});
```

All types include JSDoc documentation available in your IDE:
- Hover over types for detailed information
- View example code in JSDoc comments
- Get autocomplete for all methods

## Configuration

### Machine Keys

By default, x0x stores your machine key at `~/.x0x/machine.key`. To use a custom location:

```javascript
const agent = await Agent.builder()
  .withMachineKey('/custom/path/to/key')
  .build();
```

### Custom Keypairs

For testing or advanced scenarios:

```javascript
const keyBytes = Buffer.alloc(32); // In production, use proper key management
const agent = await Agent.builder()
  .withMachineKeypair(keyBytes)
  .withAgentKeypair(keyBytes)
  .build();
```

## Network Architecture

x0x uses a multi-layer P2P architecture:

1. **Transport Layer**: QUIC with native NAT traversal (no STUN/TURN)
2. **Overlay Network**: Gossip-based peer discovery and message propagation
3. **Encryption**: Post-quantum cryptography (ML-DSA-65, ML-KEM-768)
4. **Synchronization**: CRDT task lists for conflict-free collaboration

All layers are transparent to the application.

## Security Considerations

- **Never log task IDs or agent IDs** - They contain cryptographic material
- **Store machine keys securely** - Default location is `~/.x0x/machine.key` with restricted permissions
- **Use HTTPS for production** - If exposing via HTTP, add TLS layer
- **Validate task list ownership** - Don't assume all agents in a task list are trusted

## Contributing

Contributions welcome! See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## License

Dual licensed under AGPL-3.0-or-later and Commercial License.

See [LICENSE](../../LICENSE) for details.

## Support

- GitHub Issues: https://github.com/saorsa-labs/x0x/issues
- Documentation: https://github.com/saorsa-labs/x0x
- Contact: david@saorsalabs.com
