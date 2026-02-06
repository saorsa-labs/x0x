/**
 * x0x - Secure P2P Communication for AI Agents with CRDT Collaboration
 *
 * Post-quantum secure P2P gossip network for AI agents with CRDT-based
 * collaborative task lists. Built on ant-quic (QUIC transport with native
 * NAT traversal and post-quantum cryptography) and saorsa-gossip overlay.
 *
 * @module x0x
 */

/**
 * Checkbox state in CRDT task list
 * - Empty: Task not claimed by anyone
 * - Claimed: Task claimed by an agent
 * - Done: Task completed by an agent
 */
export type CheckboxState = 'empty' | 'claimed' | 'done';

/**
 * Machine identity derived from ML-DSA-65 keypair tied to this machine
 */
export class MachineId {
  /**
   * Get the machine ID as a hex-encoded string
   */
  toString(): string;

  /**
   * Create a MachineId from a hex-encoded string
   */
  static fromString(id: string): MachineId;
}

/**
 * Agent identity - persistent across machines, derived from ML-DSA-65 keypair
 */
export class AgentId {
  /**
   * Get the agent ID as a hex-encoded string
   */
  toString(): string;

  /**
   * Create an AgentId from a hex-encoded string
   */
  static fromString(id: string): AgentId;
}

/**
 * Agent identity with both machine and agent keys
 */
export interface Identity {
  /** Machine-specific identity */
  machineId: MachineId;
  /** Portable agent identity */
  agentId: AgentId;
}

/**
 * Event listener callback type
 */
export type EventListener<T> = (event: T) => void;

/**
 * Peer connection event - fired when an agent connects
 */
export interface PeerConnectedEvent {
  /** PeerId of the connected agent */
  peerId: string;
  /** Timestamp when connection established */
  timestamp: number;
}

/**
 * Peer disconnection event - fired when an agent disconnects
 */
export interface PeerDisconnectedEvent {
  /** PeerId of the disconnected agent */
  peerId: string;
  /** Timestamp when disconnection detected */
  timestamp: number;
}

/**
 * Message event - fired when a message is received
 */
export interface MessageEvent {
  /** Topic the message was received on */
  topic: string;
  /** Message payload as Buffer */
  payload: Buffer;
  /** PeerId of the message origin */
  origin: string;
  /** Timestamp when message was received */
  timestamp: number;
}

/**
 * Task updated event - fired when a task list is updated
 */
export interface TaskUpdatedEvent {
  /** Task ID that was updated */
  taskId: string;
  /** Type of update: 'added', 'claimed', 'completed', 'removed', 'reordered' */
  updateType: string;
  /** Timestamp of the update */
  timestamp: number;
}

/**
 * Error event - fired when an error occurs
 */
export interface ErrorEvent {
  /** Error message */
  message: string;
  /** Error code if applicable */
  code?: string;
  /** Original error if wrapped */
  cause?: Error;
}

/**
 * Message sent or received on a topic
 */
export interface Message {
  /** The message topic */
  topic: string;
  /** Message payload */
  payload: Buffer;
  /** PeerId of message origin */
  origin: string;
}

/**
 * Subscription handle for topic messages
 */
export class Subscription {
  /**
   * Unsubscribe from the topic and stop receiving messages
   */
  unsubscribe(): Promise<void>;
}

/**
 * Builder for creating agents with custom configuration
 */
export class AgentBuilder {
  /**
   * Set the path to the machine key file
   * @param path Path to machine.key file
   */
  withMachineKey(path: string): AgentBuilder;

  /**
   * Set the agent keypair (internal - for advanced use)
   * @param keypair Agent keypair bytes
   */
  withAgentKey(keypair: Buffer): AgentBuilder;

  /**
   * Build and create the agent
   */
  build(): Promise<Agent>;
}

/**
 * x0x Agent - the primary interface for P2P communication
 */
export class Agent {
  /**
   * Create a new agent with default configuration
   * Automatically generates machine identity and agent identity
   */
  static create(): Promise<Agent>;

  /**
   * Create an agent builder for custom configuration
   */
  static builder(): AgentBuilder;

  /**
   * Get the agent's identity information
   */
  identity(): Identity;

  /**
   * Get the agent's peer ID (derived from public key)
   */
  peerId(): string;

  /**
   * Join the x0x network
   * Initiates connections to known peers and begins gossip participation
   */
  joinNetwork(): Promise<void>;

  /**
   * Subscribe to messages on a topic
   * @param topic Topic name to subscribe to
   * @param callback Function called when messages arrive
   * @returns Subscription handle for unsubscribing
   */
  subscribe(topic: string, callback: (message: Message) => void): Subscription;

  /**
   * Publish a message to a topic
   * @param topic Topic name
   * @param payload Message payload as Buffer
   */
  publish(topic: string, payload: Buffer): Promise<void>;

  /**
   * Register an event listener
   * @param event Event type: 'connected', 'disconnected', 'message', 'taskUpdated', 'error'
   * @param listener Event callback function
   */
  on<T extends AgentEvent>(event: T, listener: EventListener<AgentEventMap[T]>): void;

  /**
   * Unregister an event listener
   * @param event Event type
   * @param listener Event callback function
   */
  off<T extends AgentEvent>(event: T, listener: EventListener<AgentEventMap[T]>): void;

  /**
   * Create a new task list
   * @param name Task list name
   * @param topic Gossip topic for synchronization
   */
  createTaskList(name: string, topic: string): Promise<TaskList>;

  /**
   * Join an existing task list
   * @param topic Gossip topic of the task list
   */
  joinTaskList(topic: string): Promise<TaskList>;
}

/** Event type names for agent */
export type AgentEvent = 'connected' | 'disconnected' | 'message' | 'taskUpdated' | 'error';

/** Event type mapping */
export interface AgentEventMap {
  'connected': PeerConnectedEvent;
  'disconnected': PeerDisconnectedEvent;
  'message': MessageEvent;
  'taskUpdated': TaskUpdatedEvent;
  'error': ErrorEvent;
}

/**
 * Snapshot of a task item for viewing
 */
export interface TaskSnapshot {
  /** Unique task ID (hex-encoded) */
  id: string;
  /** Task title */
  title: string;
  /** Task description */
  description: string;
  /** Current checkbox state */
  state: CheckboxState;
  /** Agent ID of task assignee (if claimed/done) */
  assignee?: string;
  /** Task priority (0-100) */
  priority: number;
}

/**
 * Collaborative task list with CRDT synchronization
 */
export class TaskList {
  /**
   * Add a new task to the list
   * @param title Task title
   * @param description Task description
   * @returns Promise resolving to the new task's ID
   */
  addTask(title: string, description: string): Promise<string>;

  /**
   * Claim a task (mark as in-progress)
   * @param taskId Task ID (hex-encoded)
   */
  claimTask(taskId: string): Promise<void>;

  /**
   * Complete a task
   * @param taskId Task ID (hex-encoded)
   */
  completeTask(taskId: string): Promise<void>;

  /**
   * Get a snapshot of all tasks in current state
   * @returns Promise resolving to array of task snapshots
   */
  listTasks(): Promise<TaskSnapshot[]>;

  /**
   * Reorder tasks in the list
   * @param taskIds Array of task IDs in desired order
   */
  reorder(taskIds: string[]): Promise<void>;

  /**
   * Manually synchronize this task list with the network
   * Used to force reconciliation with peers
   */
  sync(): Promise<void>;
}

/**
 * Platform detection information
 */
export interface PlatformInfo {
  /** Platform string (e.g., 'darwin-arm64', 'linux-x64-gnu') */
  platform: string;
  /** NAPI-RS triplet if known */
  triplet: string | null;
}

/**
 * Load a native binding for the current platform
 */
export function __loadNative__(): any;

/**
 * Load the WASM fallback binding
 */
export function __loadWasm__(): any;

/**
 * Platform information for the current runtime
 */
export const __platform__: PlatformInfo;

/**
 * Re-export all public types for namespace convenience
 */
export { CheckboxState, Agent, AgentBuilder, TaskList, TaskSnapshot, Message, Subscription };
export { MachineId, AgentId, Identity };
export { PeerConnectedEvent, PeerDisconnectedEvent, MessageEvent, TaskUpdatedEvent, ErrorEvent };
