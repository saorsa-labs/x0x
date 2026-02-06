/**
 * Basic Agent Example
 * 
 * Create an agent, join the network, and send/receive messages
 * 
 * Run: node examples/basic-agent.js
 */

const { Agent } = require('../index');

async function main() {
  try {
    console.log('Creating x0x agent...');
    const agent = await Agent.create();

    console.log('Agent created!');
    console.log('PeerId:', agent.peerId());
    
    const identity = agent.identity();
    console.log('Agent ID:', identity.agentId.toString());
    console.log('Machine ID:', identity.machineId.toString());

    console.log('\nJoining network...');
    try {
      await agent.joinNetwork();
      console.log('Connected to network');
    } catch (e) {
      console.log('(Network join is a stub pending Phase 1.3)');
    }

    console.log('\nSetting up event listeners...');
    agent.on('connected', (event) => {
      console.log('✓ Peer connected:', event.peerId);
    });

    agent.on('disconnected', (event) => {
      console.log('✗ Peer disconnected:', event.peerId);
    });

    agent.on('error', (event) => {
      console.error('✗ Error:', event.message);
    });

    console.log('\nSubscribing to "general" topic...');
    const subscription = agent.subscribe('general', (message) => {
      const payload = Buffer.isBuffer(message.payload) 
        ? message.payload.toString() 
        : message.payload;
      console.log(`[${message.topic}] ${payload}`);
    });

    console.log('\nPublishing a test message...');
    try {
      await agent.publish('general', Buffer.from('Hello from Agent!'));
      console.log('Message published');
    } catch (e) {
      console.log('(Publish is a stub pending Phase 1.3)');
    }

    console.log('\nAgent is running. Press Ctrl+C to exit.');
    console.log('You can use this agent as a base for more complex examples.\n');

    // Keep the process alive
    await new Promise(() => {});
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

main();
