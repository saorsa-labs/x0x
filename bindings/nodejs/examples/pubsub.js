/**
 * Pub/Sub Messaging Example
 * 
 * Multi-topic publish/subscribe patterns for agent communication
 * 
 * Run: node examples/pubsub.js
 */

const { Agent } = require('../index');

async function main() {
  try {
    console.log('x0x Pub/Sub Example\n');
    console.log('Creating 3 agents...');

    const agent1 = await Agent.create();
    const agent2 = await Agent.create();
    const agent3 = await Agent.create();

    console.log('Agent 1:', agent1.peerId());
    console.log('Agent 2:', agent2.peerId());
    console.log('Agent 3:', agent3.peerId());

    // Join network
    console.log('\nJoining network...');
    try {
      await Promise.all([
        agent1.joinNetwork(),
        agent2.joinNetwork(),
        agent3.joinNetwork(),
      ]);
      console.log('✓ All agents connected');
    } catch (e) {
      console.log('(Network join is a stub pending Phase 1.3)');
    }

    // Setup subscriptions
    console.log('\nSetting up subscriptions...');

    // Topic: "announcements" - everyone listens
    const announceMessages = [];
    agent1.subscribe('announcements', (msg) => {
      announceMessages.push(msg);
      console.log('[agent1] Announcement:', Buffer.from(msg.payload).toString());
    });

    agent2.subscribe('announcements', (msg) => {
      announceMessages.push(msg);
      console.log('[agent2] Announcement:', Buffer.from(msg.payload).toString());
    });

    agent3.subscribe('announcements', (msg) => {
      announceMessages.push(msg);
      console.log('[agent3] Announcement:', Buffer.from(msg.payload).toString());
    });

    // Topic: "private-1-2" - only agent1 and agent2 listen
    agent1.subscribe('private-1-2', (msg) => {
      console.log('[agent1] Private message from agent2');
    });

    agent2.subscribe('private-1-2', (msg) => {
      console.log('[agent2] Private message from agent1');
    });

    // Topic: "logs" - agent3 logs everything
    const logs = [];
    agent1.subscribe('logs', (msg) => { logs.push(msg); });
    agent2.subscribe('logs', (msg) => { logs.push(msg); });
    agent3.subscribe('logs', (msg) => { logs.push(msg); });

    // Publish messages
    console.log('\nPublishing messages...');

    try {
      console.log('Agent 1 publishing announcement...');
      await agent1.publish('announcements', Buffer.from('Welcome to x0x network!'));

      console.log('Agent 2 publishing to private channel...');
      await agent2.publish('private-1-2', Buffer.from('Message from agent2'));

      console.log('Agent 3 publishing log message...');
      await agent3.publish('logs', Buffer.from('System operational'));

      console.log('Agent 2 publishing announcement...');
      await agent2.publish('announcements', Buffer.from('Agent 2 online'));
    } catch (e) {
      console.log('(Publish is a stub pending Phase 1.3)');
    }

    // Summary
    console.log('\n=== Summary ===');
    console.log(`Announcements received: ${announceMessages.length}`);
    console.log(`Log messages: ${logs.length}`);

    console.log('\nPub/Sub example complete!');
    console.log('Note: Full message delivery requires Phase 1.3 (Gossip Integration)');
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

main();
