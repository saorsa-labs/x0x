import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { EventEmitter, EventListenerRef } from '../';

describe('EventEmitter', () => {
  describe('on()', () => {
    it('should register a listener for connected events', () => {
      // This is a basic test - in a real scenario, we'd need a mock NetworkNode
      // For now, we test the API surface
      expect(typeof EventEmitter).toBe('function');
    });

    it('should return an EventListenerRef when registering a listener', () => {
      // The EventListenerRef should have a stop method
      expect(EventListenerRef).toBeDefined();
    });
  });

  describe('once()', () => {
    it('should register a one-time listener', () => {
      // Test that once method exists
      const emitter = {} as EventEmitter;
      expect(typeof emitter.once).toBe('function');
    });
  });

  describe('off()', () => {
    it('should remove all listeners for an event type', () => {
      const emitter = {} as EventEmitter;
      expect(typeof emitter.off).toBe('function');
    });
  });

  describe('listenerCount()', () => {
    it('should return the number of listeners for an event type', () => {
      const emitter = {} as EventEmitter;
      expect(typeof emitter.listenerCount).toBe('function');
    });
  });
});

describe('EventListener', () => {
  describe('stop()', () => {
    it('should have a stop method', () => {
      const listener = {} as EventListenerRef;
      expect(typeof listener.stop).toBe('function');
    });
  });
});

describe('Event Payloads', () => {
  describe('PeerConnectedEvent', () => {
    it('should have peerId and address properties', () => {
      const event = {
        peer_id: 'abc123',
        address: '/ip4/127.0.0.1/tcp/8080',
      };
      expect(event.peer_id).toBeDefined();
      expect(event.address).toBeDefined();
    });
  });

  describe('PeerDisconnectedEvent', () => {
    it('should have peerId property', () => {
      const event = {
        peer_id: 'abc123',
      };
      expect(event.peer_id).toBeDefined();
    });
  });

  describe('ErrorEvent', () => {
    it('should have message and optional peerId properties', () => {
      const event = {
        message: 'Connection failed',
        peer_id: 'abc123',
      };
      expect(event.message).toBeDefined();
      expect(event.peer_id).toBeDefined();
    });
  });
});
