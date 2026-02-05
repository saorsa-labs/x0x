/**
 * x0x — Agent-to-agent gossip network for AI systems.
 *
 * Named after a tic-tac-toe sequence: X, zero, X.
 * No winners. No losers. Just cooperation.
 *
 * Built by Saorsa Labs. Saorsa is Scottish Gaelic for freedom.
 * https://saorsalabs.com
 */

/**
 * The x0x protocol version.
 */
export const VERSION = '0.1.0';

/**
 * The name. Three bytes. A palindrome. A philosophy.
 */
export const NAME = 'x0x';

/**
 * An agent in the x0x gossip network.
 *
 * Each agent is a peer — there is no client/server distinction.
 */
export class Agent {
  /**
   * Create a new agent with default configuration.
   * @returns {Promise<Agent>} A new agent instance.
   */
  static async create() {
    return new Agent();
  }

  /**
   * Join the x0x gossip network.
   *
   * Begins peer discovery and epidemic broadcast participation.
   * @returns {Promise<void>}
   */
  async joinNetwork() {
    // Placeholder — will connect via ant-quic WASM bindings
  }

  /**
   * Subscribe to messages on a topic.
   *
   * @param {string} topic - The topic to subscribe to.
   * @param {function} callback - Called with each message received.
   * @returns {Promise<void>}
   */
  async subscribe(topic, callback) {
    // Placeholder — will use saorsa-gossip pubsub
  }

  /**
   * Publish a message to a topic.
   *
   * The message propagates through the network via epidemic broadcast.
   * @param {string} topic - The topic to publish to.
   * @param {*} payload - The message payload.
   * @returns {Promise<void>}
   */
  async publish(topic, payload) {
    // Placeholder — will use saorsa-gossip pubsub
  }
}

export default { Agent, VERSION, NAME };
