/**
 * x0x - Agent-to-Agent Secure Communication Network
 *
 * TypeScript type definitions for x0x Node.js bindings.
 * These types provide full IDE autocomplete and type safety for the x0x SDK.
 */

// ============================================================================
// Identity Types
// ============================================================================

/**
 * Machine-level cryptographic identity.
 * A MachineId represents a unique machine/device that can run agents.
 */
declare class MachineId {
  /**
   * Convert the MachineId to a hex-encoded string.
   */
  toString(): string;

  /**
   * Create a MachineId from a hex-encoded string.
   */
  static fromString(hex: string): MachineId;
}

/**
 * Agent-level cryptographic identity.
 * An AgentId uniquely identifies an individual AI agent.
 */
declare class AgentId {
  /**
   * Convert the AgentId to a hex-encoded string.
   */
  toString(): string;

  /**
   * Create an AgentId from a hex-encoded string.
   */
  static fromString(hex: string): AgentId;
}

// ============================================================================
// Agent and Network Types
// ============================================================================

/**
 * Message received from the network.
 */
interface Message {
  /**
   * Topic this message was received on
   */
  topic: string;
  /**
   * Sender's peer ID (hex-encoded)
   */
  origin: string;
  /**
   * Message payload (binary data)
   */
  payload: Buffer;
}

/**
 * Handle for managing a pub/sub subscription.
 */
interface Subscription {
  /**
   * Stop listening to new messages on this subscription.
   */
  unsubscribe(): Promise<void>;
}

/**
 * Configuration for Agent creation.
 */
interface AgentConfig {
  /**
   * Optional path to machine key file (defaults to ~/.x0x/machine.key)
   */
  machineKeyPath?: string;

  /**
   * Optional custom machine keypair (overrides machineKeyPath)
   */
  machineKey?: Buffer;

  /**
   * Optional custom agent keypair
   */
  agentKey?: Buffer;
}

/**
 * Main agent interface for x0x network operations.
 *
 * The Agent is the primary interface for:
 * - Joining the network
 * - Publishing and subscribing to messages
 * - Creating and joining collaborative task lists
 * - Listening to network events (connected, disconnected, etc.)
 */
declare class Agent {
  /**
   * Create a new agent with default configuration.
   *
   * @returns Promise resolving to a new Agent instance
   *
   * @example
   * const agent = await Agent.create();
   * await agent.joinNetwork();
   */
  static create(): Promise<Agent>;

  /**
   * Create a new agent builder for custom configuration.
   *
   * @returns AgentBuilder instance for chainable configuration
   *
   * @example
   * const agent = await Agent.builder()
   *   .withMachineKey('/path/to/key')
   *   .build();
   */
  static builder(): AgentBuilder;

  /**
   * Join the x0x gossip network.
   *
   * @returns Promise that resolves when the agent is connected
   *
   * @example
   * await agent.joinNetwork();
   * console.log('Connected to network');
   */
  joinNetwork(): Promise<void>;

  /**
   * Subscribe to messages on a topic.
   *
   * @param topic - Topic name to subscribe to
   * @param callback - Function called when a message is received
   * @returns Subscription handle for cleanup
   *
   * @example
   * const sub = agent.subscribe('chat', (msg) => {
   *   console.log('Message:', msg.payload.toString());
   * });
   *
   * // Later:
   * await sub.unsubscribe();
   */
  subscribe(topic: string, callback: (msg: Message) => void): Subscription;

  /**
   * Publish a message to a topic.
   *
   * @param topic - Topic name to publish to
   * @param payload - Binary message data
   * @returns Promise that resolves when the message is published
   *
   * @example
   * await agent.publish('chat', Buffer.from('Hello!'));
   */
  publish(topic: string, payload: Buffer): Promise<void>;

  /**
   * Create a new collaborative task list.
   *
   * @param name - Human-readable list name
   * @param topic - Unique topic identifier for synchronization
   * @returns Promise resolving to a TaskList instance
   *
   * @example
   * const tasks = await agent.createTaskList('Sprint 1', 'sprint-1-tasks');
   * const taskId = await tasks.addTask('Design API', 'RESTful endpoints');
   */
  createTaskList(name: string, topic: string): Promise<TaskList>;

  /**
   * Join an existing collaborative task list.
   *
   * @param topic - Topic identifier of the task list to join
   * @returns Promise resolving to a TaskList instance
   *
   * @example
   * const tasks = await agent.joinTaskList('sprint-1-tasks');
   * const snapshot = await tasks.listTasks();
   */
  joinTaskList(topic: string): Promise<TaskList>;

  /**
   * Register event listener for 'connected' events.
   * Fires when the agent successfully joins the network.
   *
   * @param event - Event type ('connected')
   * @param callback - Called with PeerConnectedEvent
   */
  on(event: 'connected', callback: (e: PeerConnectedEvent) => void): EventListener;

  /**
   * Register event listener for 'disconnected' events.
   * Fires when a peer disconnects from the network.
   */
  on(event: 'disconnected', callback: (e: PeerDisconnectedEvent) => void): EventListener;

  /**
   * Register event listener for 'message' events.
   * Fires when a broadcast message is received.
   */
  on(event: 'message', callback: (e: Message) => void): EventListener;

  /**
   * Register event listener for 'taskUpdated' events.
   * Fires when a task list is synchronized.
   */
  on(event: 'taskUpdated', callback: (taskId: string) => void): EventListener;

  /**
   * Register event listener for 'error' events.
   * Fires when a network error occurs.
   */
  on(event: 'error', callback: (e: ErrorEvent) => void): EventListener;

  /**
   * Register a one-time event listener (fires once then unregisters).
   */
  once(event: string, callback: (e: any) => void): EventListener;

  /**
   * Remove all listeners for an event type.
   *
   * @param event - Event type to remove listeners from
   */
  off(event: string): void;

  /**
   * Get the count of listeners for an event type.
   *
   * @param event - Event type to count
   * @returns Number of registered listeners
   */
  listenerCount(event: string): number;
}

/**
 * Builder for configuring Agent creation.
 */
declare class AgentBuilder {
  /**
   * Set the machine key file path.
   *
   * @param path - Path to machine key file
   * @returns This builder for chaining
   */
  withMachineKey(path: string): AgentBuilder;

  /**
   * Set a custom machine keypair.
   *
   * @param keypair - Binary keypair data
   * @returns This builder for chaining
   */
  withMachineKeypair(keypair: Buffer): AgentBuilder;

  /**
   * Set a custom agent keypair.
   *
   * @param keypair - Binary keypair data
   * @returns This builder for chaining
   */
  withAgentKeypair(keypair: Buffer): AgentBuilder;

  /**
   * Build the Agent with the current configuration.
   *
   * @returns Promise resolving to a configured Agent
   */
  build(): Promise<Agent>;
}

// ============================================================================
// Task List Types
// ============================================================================

/**
 * Checkbox state for a task.
 */
type CheckboxState = 'empty' | 'claimed' | 'done';

/**
 * Snapshot of a task's current state.
 */
interface TaskSnapshot {
  /**
   * Task ID (hex-encoded)
   */
  id: string;

  /**
   * Task title
   */
  title: string;

  /**
   * Detailed description
   */
  description: string;

  /**
   * Current state: 'empty', 'claimed', or 'done'
   */
  state: CheckboxState;

  /**
   * Agent ID of the assignee (if claimed or done)
   */
  assignee?: string;

  /**
   * Display priority (0-255, higher = more important)
   */
  priority: number;
}

/**
 * Collaborative CRDT-based task list.
 *
 * TaskList provides conflict-free task management with automatic
 * synchronization across agents via the gossip network.
 *
 * Each task has three states:
 * - empty ([ ]) - Available to be claimed
 * - claimed ([-]) - Assigned to an agent
 * - done ([x]) - Completed
 */
declare class TaskList {
  /**
   * Add a new task to the list.
   *
   * The task starts in the empty state and can be claimed by any agent.
   *
   * @param title - Task title (e.g., "Implement feature X")
   * @param description - Detailed description of the task
   * @returns Promise resolving to the task ID (hex-encoded string)
   *
   * @example
   * const taskId = await taskList.addTask(
   *   "Fix bug in network layer",
   *   "The connection timeout is too aggressive"
   * );
   * console.log(`Created task: ${taskId}`);
   */
  addTask(title: string, description: string): Promise<string>;

  /**
   * Claim a task for yourself.
   *
   * Changes the task state from empty [ ] to claimed [-] and assigns
   * it to your agent ID. If multiple agents claim simultaneously, the
   * CRDT resolves the conflict deterministically.
   *
   * @param taskId - ID of the task to claim (hex-encoded string)
   * @returns Promise that resolves when the claim is applied locally
   *
   * @example
   * await taskList.claimTask(taskId);
   * console.log("Task claimed!");
   */
  claimTask(taskId: string): Promise<void>;

  /**
   * Mark a task as complete.
   *
   * Changes the task state to done [x]. Only the agent that claimed
   * the task can complete it (enforced by CRDT rules).
   *
   * @param taskId - ID of the task to complete (hex-encoded string)
   * @returns Promise that resolves when the completion is applied locally
   *
   * @example
   * await taskList.completeTask(taskId);
   * console.log("Task completed!");
   */
  completeTask(taskId: string): Promise<void>;

  /**
   * Get a snapshot of all tasks in the list.
   *
   * Returns the current state of all tasks with their metadata.
   *
   * @returns Promise resolving to an array of TaskSnapshot objects
   *
   * @example
   * const tasks = await taskList.listTasks();
   * for (const task of tasks) {
   *   console.log(`[${task.state}] ${task.title}`);
   * }
   */
  listTasks(): Promise<TaskSnapshot[]>;

  /**
   * Reorder tasks in the list.
   *
   * Changes the display order of tasks. The CRDT uses Last-Write-Wins
   * semantics for ordering.
   *
   * @param taskIds - Array of task IDs in the desired order
   * @returns Promise that resolves when the reordering is applied locally
   *
   * @example
   * await taskList.reorder([taskId1, taskId2, taskId3]);
   */
  reorder(taskIds: string[]): Promise<void>;
}

// ============================================================================
// Event Types
// ============================================================================

/**
 * Fired when a peer connects to the network.
 */
interface PeerConnectedEvent {
  /**
   * Peer ID (hex-encoded)
   */
  peer_id: string;

  /**
   * Peer network address (multiaddr format)
   */
  address: string;
}

/**
 * Fired when a peer disconnects from the network.
 */
interface PeerDisconnectedEvent {
  /**
   * Peer ID (hex-encoded)
   */
  peer_id: string;
}

/**
 * Fired when a network error occurs.
 */
interface ErrorEvent {
  /**
   * Error message
   */
  message: string;

  /**
   * Optional peer ID if error is peer-specific
   */
  peer_id?: string;
}

/**
 * Handle for managing event listeners.
 * Call stop() to unregister the listener.
 */
interface EventListener {
  /**
   * Stop listening to events and unregister the listener.
   */
  stop(): void;
}

// ============================================================================
// Module Exports
// ============================================================================

export {
  // Identity types
  MachineId,
  AgentId,
  // Agent types
  Agent,
  AgentBuilder,
  Message,
  Subscription,
  AgentConfig,
  // Task list types
  TaskList,
  TaskSnapshot,
  CheckboxState,
  // Event types
  PeerConnectedEvent,
  PeerDisconnectedEvent,
  ErrorEvent,
  EventListener,
};
