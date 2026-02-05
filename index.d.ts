/**
 * x0x — Agent-to-agent gossip network for AI systems.
 */

export declare const VERSION: string;
export declare const NAME: string;

export interface Message {
  origin: string;
  payload: unknown;
  topic: string;
}

export declare class Agent {
  static create(): Promise<Agent>;
  joinNetwork(): Promise<void>;
  subscribe(topic: string, callback: (msg: Message) => void): Promise<void>;
  publish(topic: string, payload: unknown): Promise<void>;
}

declare const _default: {
  Agent: typeof Agent;
  VERSION: string;
  NAME: string;
};

export default _default;
