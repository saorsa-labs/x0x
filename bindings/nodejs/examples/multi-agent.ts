/**
 * Multi-Agent Coordination Example (TypeScript)
 * 
 * Demonstrates coordinated task management between multiple agents
 * 
 * Run: npm run ts-node examples/multi-agent.ts
 */

import { Agent, TaskList, CheckboxState } from '../index';

async function main(): Promise<void> {
  console.log('Multi-Agent Coordination Example\n');

  // Create agents
  console.log('Creating 4 agents...');
  const agents = await Promise.all([
    Agent.create(),
    Agent.create(),
    Agent.create(),
    Agent.create(),
  ]);

  const [alice, bob, charlie, diana] = agents;

  console.log('Alice:', alice.peerId());
  console.log('Bob:  ', bob.peerId());
  console.log('Charlie:', charlie.peerId());
  console.log('Diana:', diana.peerId());

  // Join network
  console.log('\nAll agents joining network...');
  try {
    await Promise.all(agents.map(a => a.joinNetwork()));
    console.log('✓ All connected');
  } catch (e) {
    console.log('(Network join is a stub pending Phase 1.3)');
  }

  // Setup event listeners
  console.log('\nSetting up listeners...');
  agents.forEach((agent, idx) => {
    const names = ['Alice', 'Bob', 'Charlie', 'Diana'];
    agent.on('connected', (event) => {
      console.log(`${names[idx]} sees new peer: ${event.peerId.substring(0, 8)}...`);
    });
  });

  // Create shared task list
  console.log('\nAlice creating shared task list: "Group Project"');
  const projectList: TaskList = await alice.createTaskList(
    'Group Project',
    'group-project-q1-2026'
  );

  // Other agents join
  console.log('Other agents joining the task list...');
  const bobTasks = await bob.joinTaskList('group-project-q1-2026');
  const charlieTasks = await charlie.joinTaskList('group-project-q1-2026');
  const dianaTasks = await diana.joinTaskList('group-project-q1-2026');

  // Add tasks
  console.log('\nAdding tasks...');
  const tasks = {
    design: await projectList.addTask(
      'Design system architecture',
      'Create high-level design'
    ),
    api: await projectList.addTask(
      'Implement API',
      'REST endpoints'
    ),
    database: await projectList.addTask(
      'Setup database',
      'PostgreSQL schema'
    ),
    testing: await projectList.addTask(
      'Write tests',
      'Unit and integration tests'
    ),
  };

  console.log(`✓ Added ${Object.keys(tasks).length} tasks`);

  // Agents claim and complete tasks
  console.log('\nAgents claiming tasks...');
  try {
    // Alice takes design
    await projectList.claimTask(tasks.design);
    console.log('Alice claimed: Design');

    // Bob takes API
    await bobTasks.claimTask(tasks.api);
    console.log('Bob claimed: API');

    // Charlie takes database
    await charlieTasks.claimTask(tasks.database);
    console.log('Charlie claimed: Database');

    // Diana takes testing
    await dianaTasks.claimTask(tasks.testing);
    console.log('Diana claimed: Testing');

    // Complete some tasks
    console.log('\nCompleting tasks...');
    await projectList.completeTask(tasks.design);
    console.log('Alice completed: Design');

    await bobTasks.completeTask(tasks.api);
    console.log('Bob completed: API');
  } catch (e) {
    console.log('(Task operations are stubs pending Phase 1.3)');
  }

  // View final state
  console.log('\nFinal task list:');
  const finalTasks = await projectList.listTasks();
  finalTasks.forEach((task) => {
    const stateIcon: Record<CheckboxState, string> = {
      'empty': '□',
      'claimed': '◐',
      'done': '☑',
    };
    console.log(
      `  ${stateIcon[task.state]} ${task.title} (priority: ${task.priority})`
    );
  });

  // Sync all task lists
  console.log('\nSynchronizing...');
  try {
    await Promise.all([
      projectList.sync(),
      bobTasks.sync(),
      charlieTasks.sync(),
      dianaTasks.sync(),
    ]);
    console.log('✓ All synchronized');
  } catch (e) {
    console.log('(Sync is a stub pending Phase 1.3)');
  }

  console.log('\nMulti-agent coordination example complete!');
  console.log('In production, agents would remain connected and collaborate');
  console.log('continuously using CRDT-based synchronization.');
}

main().catch((error) => {
  console.error('Error:', error.message);
  process.exit(1);
});
