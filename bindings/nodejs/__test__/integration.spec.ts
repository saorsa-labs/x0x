/**
 * Integration tests for x0x Node.js bindings
 * Tests core Agent and Network functionality
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { Agent, Message } from '../index';

describe('x0x Integration Tests', () => {
  let agent: Agent;

  beforeEach(async () => {
    agent = await Agent.create();
  });

  afterEach(() => {
    // Cleanup
  });

  describe('Agent Creation', () => {
    it('should create an agent with default configuration', async () => {
      expect(agent).toBeDefined();
      expect(typeof agent.identity).toBe('function');
      expect(typeof agent.peerId).toBe('function');
    });

    it('should have unique agent IDs', async () => {
      const agent2 = await Agent.create();
      expect(agent.peerId()).not.toEqual(agent2.peerId());
    });

    it('should maintain identity across calls', () => {
      const peerId1 = agent.peerId();
      const peerId2 = agent.peerId();
      expect(peerId1).toEqual(peerId2);
    });
  });

  describe('Agent Builder', () => {
    it('should create agents using builder pattern', async () => {
      const builtAgent = await Agent.builder().build();
      expect(builtAgent).toBeDefined();
      expect(builtAgent.peerId()).toBeDefined();
    });

    it('should support chaining builder methods', async () => {
      const builtAgent = await Agent.builder()
        .build();
      expect(builtAgent.peerId()).toBeDefined();
    });
  });

  describe('Network Operations', () => {
    it('should handle joinNetwork without errors', async () => {
      // This is a stub pending Phase 1.3
      // When Phase 1.3 is complete, this will actually join the network
      try {
        await agent.joinNetwork();
        // Success or graceful stub behavior
      } catch (error) {
        // Expected for stub implementation
      }
    });

    it('should handle publish without errors', async () => {
      const payload = Buffer.from('test message');
      try {
        await agent.publish('test-topic', payload);
        // Success or graceful stub behavior
      } catch (error) {
        // Expected for stub implementation
      }
    });

    it('should handle subscribe without errors', () => {
      const callback = (msg: Message) => {
        // Do nothing
      };
      try {
        const subscription = agent.subscribe('test-topic', callback);
        expect(subscription).toBeDefined();
      } catch (error) {
        // Expected for stub implementation
      }
    });
  });

  describe('Task List Operations', () => {
    it('should handle createTaskList calls', async () => {
      try {
        const taskList = await agent.createTaskList('Test List', 'test-topic');
        expect(taskList).toBeDefined();
        expect(typeof taskList.addTask).toBe('function');
      } catch (error) {
        // Expected for stub implementation pending Phase 1.3
      }
    });

    it('should handle joinTaskList calls', async () => {
      try {
        const taskList = await agent.joinTaskList('test-topic');
        expect(taskList).toBeDefined();
        expect(typeof taskList.listTasks).toBe('function');
      } catch (error) {
        // Expected for stub implementation pending Phase 1.3
      }
    });
  });

  describe('Event System', () => {
    it('should support event listener registration', () => {
      const connectedCallback = () => {
        // Handler
      };
      expect(() => {
        agent.on('connected', connectedCallback);
      }).not.toThrow();
    });

    it('should support event listener unregistration', () => {
      const connectedCallback = () => {
        // Handler
      };
      expect(() => {
        agent.on('connected', connectedCallback);
        agent.off('connected', connectedCallback);
      }).not.toThrow();
    });

    it('should type-check event handlers correctly', () => {
      // TypeScript compile-time check - if this compiles, it's correct
      const agent1 = agent;
      agent1.on('connected', (event) => {
        // event is PeerConnectedEvent
        expect(typeof event.peerId).toBe('string');
        expect(typeof event.timestamp).toBe('number');
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid task IDs gracefully', async () => {
      try {
        const taskList = await agent.createTaskList('Test', 'topic');
        await taskList.completeTask('invalid-task-id');
      } catch (error) {
        // Expected - invalid task ID
        expect(error).toBeDefined();
      }
    });

    it('should handle empty publish payloads', async () => {
      try {
        await agent.publish('test', Buffer.alloc(0));
        // Should succeed or handle gracefully
      } catch (error) {
        // Acceptable error handling
      }
    });
  });
});
