# Phase 2.1: napi-rs Node.js Bindings - Implementation Plan

**Phase**: 2.1
**Name**: napi-rs Node.js Bindings
**Status**: Planning Complete
**Created**: 2026-02-05
**Estimated Tasks**: 12

---

## Overview

Build a complete TypeScript SDK for x0x using napi-rs v3, exposing the Rust core library to Node.js applications. This phase creates platform-specific native bindings and WASM fallback, auto-generated TypeScript types, and a Node.js EventEmitter-based event system for async operations.

The bindings will expose:
- Agent identity creation and management
- Network joining and peer discovery
- Pub/sub messaging
- Collaborative task lists with CRDT synchronization
- TypeScript type safety throughout

---

## Task Breakdown

### Task 1: Initialize napi-rs Project Structure
**Files**:
- `bindings/nodejs/package.json`
- `bindings/nodejs/Cargo.toml`
- `bindings/nodejs/build.rs`
- `bindings/nodejs/tsconfig.json`
- `bindings/nodejs/.npmignore`

Initialize the napi-rs v3 project with proper directory structure and dependencies. Configure Cargo workspace to link with x0x core library.

**Requirements:**
- Add napi-rs v3 dependencies: `napi = "3"`, `napi-derive = "3"`
- Add `@napi-rs/cli` as dev dependency in package.json
- Configure `[lib]` with `crate-type = ["cdylib"]` in Cargo.toml
- Set up TypeScript compiler configuration for type generation
- Add napi-rs build script for automatic type generation
- Configure workspace in root Cargo.toml to include `bindings/nodejs`

**Tests**: Verify `cargo build` and `npm install` both succeed without errors.

---

### Task 2: Agent Identity Bindings - MachineId and AgentId
**Files**:
- `bindings/nodejs/src/identity.rs`
- `bindings/nodejs/src/lib.rs` (update)

Expose x0x identity types (`MachineId`, `AgentId`, `Identity`) to Node.js with proper TypeScript type generation.

**Requirements:**
- Use `#[napi]` macro on wrapper structs for `MachineId` and `AgentId`
- Implement `toString()` method returning hex-encoded string representation
- Implement `fromString()` static method for deserialization
- Export identity types from lib.rs with proper module organization
- Auto-generate TypeScript definitions for all identity types

**Tests**:
- Unit test: Create identity in Rust, convert to/from string
- Integration test: Import `{ AgentId }` in TypeScript, call `toString()`

---

### Task 3: Agent Creation and Builder Bindings
**Files**:
- `bindings/nodejs/src/agent.rs`
- `bindings/nodejs/__test__/agent.spec.ts`

Expose `Agent::new()` and `Agent::builder()` with chainable configuration methods to Node.js.

**Requirements:**
- `#[napi]` wrapper for `Agent` struct
- `Agent.create()` async static method (wraps `Agent::new()`)
- `AgentBuilder` class with `withMachineKey(path)`, `withAgentKey(keypair)` methods
- All methods return TypeScript promises
- Handle Rust Result types by throwing JavaScript errors
- Proper cleanup/Drop implementation for Agent resources

**Tests**:
- TypeScript test: `const agent = await Agent.create()`
- TypeScript test: Builder pattern with custom paths
- Test error handling when invalid paths provided

---

### Task 4: Network Operations Bindings
**Files**:
- `bindings/nodejs/src/agent.rs` (update)
- `bindings/nodejs/__test__/network.spec.ts`

Expose network operations: `joinNetwork()`, `subscribe(topic, callback)`, `publish(topic, payload)`.

**Requirements:**
- `agent.joinNetwork()` returns Promise<void>
- `agent.subscribe(topic: string, callback: (msg: Message) => void)` returns Subscription handle
- `agent.publish(topic: string, payload: Buffer)` returns Promise<void>
- `Message` interface with `origin: string`, `payload: Buffer`, `topic: string`
- Subscription handle has `unsubscribe()` method
- Use napi-rs ThreadsafeFunction for callbacks from Rust to Node.js

**Tests**:
- Mock test: Verify subscribe callback gets invoked
- Mock test: Publish succeeds and returns
- Test: Unsubscribe prevents further callbacks

---

### Task 5: Event System - Node.js EventEmitter Integration
**Files**:
- `bindings/nodejs/src/events.rs`
- `bindings/nodejs/src/agent.rs` (update)
- `bindings/nodejs/__test__/events.spec.ts`

Wrap Rust broadcast channels with Node.js EventEmitter for events: `connected`, `disconnected`, `message`, `taskUpdated`.

**Requirements:**
- Agent class extends/wraps EventEmitter pattern
- `agent.on('connected', callback)`, `agent.on('disconnected', callback)`
- `agent.on('message', (msg: Message) => void)`
- `agent.on('taskUpdated', (taskId: string) => void)`
- Spawn Tokio background task that listens to Rust broadcast channels
- Forward events to Node.js via ThreadsafeFunction
- Proper cleanup when Agent is dropped

**Tests**:
- Test: `agent.on('connected')` fires when `joinNetwork()` succeeds
- Test: `agent.on('message')` fires when message received via gossip
- Test: Event listeners can be removed with `off()`

---

### Task 6: TaskList Creation and Join Bindings
**Files**:
- `bindings/nodejs/src/task_list.rs`
- `bindings/nodejs/__test__/task_list.spec.ts`

Expose `agent.createTaskList(name, topic)` and `agent.joinTaskList(topic)`.

**Requirements:**
- `agent.createTaskList(name: string, topic: string)` returns Promise<TaskList>
- `agent.joinTaskList(topic: string)` returns Promise<TaskList>
- `TaskList` class wraps `TaskListHandle` from Rust
- Auto-generate TypeScript interface for TaskList
- Handle errors when creation/join fails

**Tests**:
- Test: Create task list, verify it returns TaskList instance
- Test: Join existing task list by topic
- Test: Error when joining non-existent topic

---

### Task 7: TaskList Operations Bindings
**Files**:
- `bindings/nodejs/src/task_list.rs` (update)
- `bindings/nodejs/__test__/task_operations.spec.ts`

Expose TaskList operations: `addTask()`, `claimTask()`, `completeTask()`, `listTasks()`, `reorder()`.

**Requirements:**
- `taskList.addTask(title: string, description: string)` returns Promise<string> (TaskId)
- `taskList.claimTask(taskId: string)` returns Promise<void>
- `taskList.completeTask(taskId: string)` returns Promise<void>
- `taskList.listTasks()` returns Promise<TaskSnapshot[]>
- `taskList.reorder(taskIds: string[])` returns Promise<void>
- `TaskSnapshot` interface: `{ id, title, description, state, assignee?, priority }`
- CheckboxState enum: Empty, Claimed, Done

**Tests**:
- Test: Add task, claim it, complete it
- Test: List tasks returns correct snapshots
- Test: Reorder tasks updates order
- Test: Concurrent claims resolve correctly (CRDT conflict-free)

---

### Task 8: WASM Fallback Target Build
**Files**:
- `bindings/nodejs/.cargo/config.toml`
- `bindings/nodejs/package.json` (update scripts)
- `.github/workflows/build-wasm.yml` (for later CI, create placeholder)

Build x0x for `wasm32-wasip1-threads` target to provide fallback when native binary unavailable.

**Requirements:**
- Add build script: `npm run build:wasm`
- Configure WASM target with WASI threads support
- Generate `x0x.wasm32-wasi.node` artifact
- Update package.json to include WASM as optional dependency
- Ensure napi-rs runtime can detect and load WASM fallback
- Document WASM limitations (e.g., no filesystem persistence without WASI)

**Tests**:
- Build test: `npm run build:wasm` succeeds
- Runtime test: Load agent in WASM mode, verify basic operations work
- Test: Agent.create() works in WASM (in-memory keys only)

---

### Task 9: Platform-Specific Package Generation
**Files**:
- `bindings/nodejs/npm/darwin-arm64/package.json`
- `bindings/nodejs/npm/darwin-x64/package.json`
- `bindings/nodejs/npm/linux-x64-gnu/package.json`
- `bindings/nodejs/npm/linux-arm64-gnu/package.json`
- `bindings/nodejs/npm/linux-x64-musl/package.json`
- `bindings/nodejs/npm/win32-x64-msvc/package.json`
- `bindings/nodejs/npm/wasm32-wasi/package.json`
- `bindings/nodejs/package.json` (update with optionalDependencies)

Generate 7 platform-specific npm packages using napi-rs CLI.

**Requirements:**
- Use `@napi-rs/cli` to scaffold platform packages
- Each package: `@x0x/core-<platform>`
- Main package `x0x` declares them as optionalDependencies
- Main package index.js detects platform and loads correct binary
- Fallback to WASM if no native binary available
- Each platform package includes only the `.node` binary for that platform
- Configure package.json with proper `cpu`, `os`, `libc` fields

**Tests**:
- Test: Install main package on macOS arm64, verify `@x0x/core-darwin-arm64` loads
- Test: Install on Linux x64, verify `@x0x/core-linux-x64-gnu` loads
- Test: Simulate unsupported platform, verify WASM fallback loads
- Test: All platform packages have correct metadata

---

### Task 10: TypeScript Type Definitions Export
**Files**:
- `bindings/nodejs/index.d.ts`
- `bindings/nodejs/src/lib.rs` (update with #[napi] annotations)
- `bindings/nodejs/package.json` (update `types` field)

Auto-generate and export complete TypeScript type definitions for all APIs.

**Requirements:**
- Configure napi-rs to auto-generate `index.d.ts` during build
- Export all types from main entry point: Agent, AgentBuilder, TaskList, TaskSnapshot, Message, Subscription
- Export enums: CheckboxState
- Export interfaces for event payloads
- Ensure generic Promise types are correctly typed
- Add JSDoc comments for all public APIs (copied from Rust docs)
- Verify TypeScript strict mode compliance

**Tests**:
- TypeScript compilation test: Import all types, verify no errors
- Type safety test: Pass wrong types to methods, verify compile errors
- IDE test: Verify autocomplete works in VSCode
- Test: JSDoc appears in IDE hover tooltips

---

### Task 11: Comprehensive Integration Tests
**Files**:
- `bindings/nodejs/__test__/integration.spec.ts`
- `bindings/nodejs/__test__/multi-agent.spec.ts`
- `bindings/nodejs/__test__/task-sync.spec.ts`

Write comprehensive integration tests covering real-world usage patterns.

**Requirements:**
- Multi-agent test: Create 2 agents, join network, exchange messages
- Task sync test: 2 agents create shared task list, verify CRDT sync
- Event test: Verify all events fire correctly during network operations
- Error handling test: Test all error paths (network failure, invalid input, etc.)
- Memory leak test: Create/destroy 100 agents, verify no leaks
- Performance test: Measure overhead of Rust↔Node.js boundary

**Tests**:
- Run with `npm test` (uses Jest or Vitest)
- All tests must pass on all 7 platforms (via CI in next phase)
- Coverage target: >90% of bindings code

---

### Task 12: Documentation and Examples
**Files**:
- `bindings/nodejs/README.md`
- `bindings/nodejs/examples/basic-agent.js`
- `bindings/nodejs/examples/task-list.js`
- `bindings/nodejs/examples/pubsub.js`
- `bindings/nodejs/examples/multi-agent.ts`

Write comprehensive documentation and runnable examples for the Node.js SDK.

**Requirements:**
- README.md with installation, quick start, API reference
- Example: Create agent, join network, subscribe to messages
- Example: Create task list, add/claim/complete tasks
- Example: Multi-agent coordination with pub/sub
- Document WASM fallback behavior and limitations
- Document platform support matrix
- Add troubleshooting section for common issues
- Include TypeScript and JavaScript examples

**Tests**:
- Verify all examples run without errors
- Test examples in both TypeScript and JavaScript
- Verify README install instructions work on clean environment

---

## Dependencies

**Rust crates:**
- `napi = "3"`
- `napi-derive = "3"`
- `tokio` (for async runtime bridge)
- `x0x` (workspace dependency)

**npm packages:**
- `@napi-rs/cli` (dev)
- `typescript` (dev)
- `jest` or `vitest` (dev, for testing)
- `@types/node` (dev)

**Build tools:**
- Rust 1.75+ with wasm32-wasip1-threads target
- Node.js 18+ (for development)

---

## Success Criteria

- [ ] All 7 platform packages build successfully
- [ ] WASM fallback works when no native binary available
- [ ] TypeScript types are fully auto-generated and accurate
- [ ] All integration tests pass on all platforms
- [ ] Event system correctly bridges Rust broadcast channels to Node.js EventEmitter
- [ ] Examples run without errors and demonstrate key features
- [ ] No memory leaks detected in stress tests
- [ ] Zero compilation warnings (Rust and TypeScript)

---

**Plan Created**: 2026-02-05
**Total Tasks**: 12
**Estimated Completion**: Phase 2.1 complete after all tasks pass review
