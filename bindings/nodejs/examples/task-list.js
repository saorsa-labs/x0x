/**
 * Task List Example
 * 
 * Create and manage collaborative task lists with CRDT synchronization
 * 
 * Run: node examples/task-list.js
 */

const { Agent } = require('../index');

async function main() {
  try {
    console.log('Creating agent and task list...\n');
    const agent = await Agent.create();

    // Create a task list
    console.log('Creating task list: "My Project"');
    const taskList = await agent.createTaskList('My Project', 'my-project-tasks');

    // Add some tasks
    console.log('\nAdding tasks...');
    const task1 = await taskList.addTask('Implement database', 'PostgreSQL setup');
    const task2 = await taskList.addTask('Create API endpoints', 'REST API');
    const task3 = await taskList.addTask('Write documentation', 'README and API docs');

    console.log(`✓ Added task 1: ${task1}`);
    console.log(`✓ Added task 2: ${task2}`);
    console.log(`✓ Added task 3: ${task3}`);

    // List all tasks
    console.log('\nListing all tasks:');
    let tasks = await taskList.listTasks();
    printTasks(tasks);

    // Claim a task
    console.log('\nClaiming task 1...');
    await taskList.claimTask(task1);

    // Complete a task
    console.log('Completing task 1...');
    await taskList.completeTask(task1);

    // List tasks again
    console.log('\nUpdated task list:');
    tasks = await taskList.listTasks();
    printTasks(tasks);

    // Reorder tasks
    console.log('\nReordering tasks...');
    await taskList.reorder([task3, task1, task2]);

    console.log('New order:');
    tasks = await taskList.listTasks();
    printTasks(tasks);

    // Sync with network
    console.log('\nSyncing with network...');
    try {
      await taskList.sync();
      console.log('✓ Synchronized');
    } catch (e) {
      console.log('(Sync is a stub pending Phase 1.3)');
    }

    console.log('\nTask list example complete!');
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

function printTasks(tasks) {
  if (tasks.length === 0) {
    console.log('  (No tasks)');
    return;
  }

  tasks.forEach((task, idx) => {
    const stateEmoji = {
      'empty': '□',
      'claimed': '◐',
      'done': '☑'
    }[task.state] || '?';

    const assignee = task.assignee ? ` (${task.assignee})` : '';
    console.log(`  ${idx + 1}. ${stateEmoji} ${task.title}${assignee}`);
    if (task.description) {
      console.log(`     ${task.description}`);
    }
  });
}

main();
