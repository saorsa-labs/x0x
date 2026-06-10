//! Scale Testing Framework and Execution
//!
//! Tests x0x local scale behavior under load: 100 agents, sustained in-process
//! message throughput, CRDT convergence time, and partition recovery.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use x0x::crdt::{Result as CrdtResult, TaskId, TaskItem, TaskList, TaskListId, TaskMetadata};
use x0x::identity::AgentId;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

const MIN_LOCAL_THROUGHPUT_MSGS_PER_SEC: f64 = 500.0;
const MAX_LOCAL_P95_LATENCY_MS: f64 = 500.0;

/// Performance metrics collector
#[derive(Debug, Clone)]
struct Metrics {
    messages_sent: Arc<AtomicU64>,
    messages_received: Arc<AtomicU64>,
    convergence_times_ms: Arc<RwLock<Vec<u64>>>,
    latencies_ms: Arc<RwLock<Vec<u64>>>,
}

impl Metrics {
    fn new() -> Self {
        Self {
            messages_sent: Arc::new(AtomicU64::new(0)),
            messages_received: Arc::new(AtomicU64::new(0)),
            convergence_times_ms: Arc::new(RwLock::new(Vec::new())),
            latencies_ms: Arc::new(RwLock::new(Vec::new())),
        }
    }

    fn record_sent(&self) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
    }

    fn record_received(&self) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
    }

    async fn record_convergence(&self, time_ms: u64) {
        self.convergence_times_ms.write().await.push(time_ms);
    }

    async fn record_latency(&self, latency_ms: u64) {
        self.latencies_ms.write().await.push(latency_ms);
    }

    async fn summary(&self) -> MetricsSummary {
        let convergence = self.convergence_times_ms.read().await.clone();
        let latencies = self.latencies_ms.read().await.clone();

        MetricsSummary {
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            mean_convergence_ms: mean(&convergence),
            p95_convergence_ms: percentile(&convergence, 95),
            mean_latency_ms: mean(&latencies),
            p95_latency_ms: percentile(&latencies, 95),
            p99_latency_ms: percentile(&latencies, 99),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct MetricsSummary {
    messages_sent: u64,
    messages_received: u64,
    mean_convergence_ms: f64,
    p95_convergence_ms: f64,
    mean_latency_ms: f64,
    p95_latency_ms: f64,
    p99_latency_ms: f64,
}

fn mean(values: &[u64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<u64>() as f64 / values.len() as f64
}

fn percentile(values: &[u64], p: u8) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = ((p as f64 / 100.0) * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)] as f64
}

fn peer_id(seed: u8) -> saorsa_gossip_types::PeerId {
    saorsa_gossip_types::PeerId::new([seed; 32])
}

fn task_for(agent_idx: usize, task_idx: usize, title_prefix: &str) -> TaskItem {
    let task_seed = (agent_idx * 10 + task_idx) as u8;
    let agent_seed = agent_idx as u8;
    let task_id = TaskId::from_bytes([task_seed; 32]);
    let meta = TaskMetadata {
        title: format!("{} {}-{}", title_prefix, agent_idx, task_idx),
        description: format!("Agent {} task {}", agent_idx, task_idx),
        priority: 128,
        created_by: AgentId([agent_seed; 32]),
        owner: None,
        created_at: 1000 + (agent_idx * 10 + task_idx) as u64,
        tags: vec!["scale".to_string()],
    };

    TaskItem::new(task_id, meta, peer_id(agent_seed))
}

fn add_scale_task(
    replica: &mut TaskList,
    agent_idx: usize,
    task_idx: usize,
    title_prefix: &str,
) -> CrdtResult<()> {
    replica.add_task(
        task_for(agent_idx, task_idx, title_prefix),
        peer_id(agent_idx as u8),
        (agent_idx * 10 + task_idx) as u64,
    )
}

fn merge_full_mesh(replicas: &mut [TaskList], metrics: &Metrics) -> CrdtResult<()> {
    let clones: Vec<TaskList> = replicas.to_vec();
    for replica in replicas {
        for other in &clones {
            replica.merge(other)?;
            metrics.record_received();
        }
    }

    Ok(())
}

#[test]
fn test_percentile_uses_nearest_rank_index() {
    let values: Vec<u64> = (1..=100).collect();

    assert_eq!(percentile(&values, 95), 95.0);
    assert_eq!(percentile(&values, 99), 99.0);
}

#[test]
fn test_percentile_handles_small_and_empty_inputs() {
    assert_eq!(percentile(&[10, 20], 50), 10.0);
    assert_eq!(percentile(&[10, 20], 100), 20.0);
    assert_eq!(percentile(&[], 95), 0.0);
}

/// Test 1: CRDT convergence with 10 agents, 50 tasks
///
/// Measures convergence time for 10 local agents performing concurrent
/// task list operations.
#[tokio::test]
async fn test_crdt_convergence_10_agents_50_tasks() -> CrdtResult<()> {
    let num_agents = 10;
    let tasks_per_agent = 5;
    let metrics = Metrics::new();

    let start = Instant::now();

    // Create 10 lightweight task lists (no network)
    let list_id = TaskListId::new([1u8; 32]);
    let mut replicas: Vec<TaskList> = (0..num_agents)
        .map(|i| {
            let peer_id = saorsa_gossip_types::PeerId::new([i as u8; 32]);
            TaskList::new(list_id, "Scale Test".to_string(), peer_id)
        })
        .collect();

    // Each replica adds 5 tasks concurrently
    for (i, replica) in replicas.iter_mut().enumerate() {
        for j in 0..tasks_per_agent {
            add_scale_task(replica, i, j, "Task")?;
            metrics.record_sent();
        }
    }

    // Simulate gossip convergence (full mesh merge)
    merge_full_mesh(&mut replicas, &metrics)?;

    let convergence_time = start.elapsed();
    metrics
        .record_convergence(convergence_time.as_millis() as u64)
        .await;

    // Verify convergence
    let expected_tasks = num_agents * tasks_per_agent;
    for replica in &replicas {
        assert_eq!(
            replica.tasks_ordered().len(),
            expected_tasks,
            "All replicas should have {} tasks",
            expected_tasks
        );
    }

    let summary = metrics.summary().await;
    println!("=== CRDT Convergence (10 agents, 50 tasks) ===");
    println!("Convergence time: {:?}", convergence_time);
    println!("Messages sent: {}", summary.messages_sent);
    println!("Mean convergence: {:.2}ms", summary.mean_convergence_ms);

    // Performance targets
    assert!(
        convergence_time < Duration::from_secs(1),
        "Convergence should be < 1s, was {:?}",
        convergence_time
    );

    Ok(())
}

/// Test 2: Message throughput (local pub/sub)
///
/// Measures sustained message throughput without network overhead.
#[tokio::test]
async fn test_message_throughput_local() -> TestResult {
    #[derive(Clone, Copy, Debug)]
    struct LocalMessage {
        sent_at: Instant,
    }

    const NUM_AGENTS: usize = 16;
    const MESSAGES_PER_AGENT: usize = 64;

    let metrics = Metrics::new();
    let mut senders = Vec::with_capacity(NUM_AGENTS);
    let mut receivers = Vec::with_capacity(NUM_AGENTS);

    for _ in 0..NUM_AGENTS {
        let (tx, mut rx) = mpsc::unbounded_channel::<LocalMessage>();
        let receiver_metrics = metrics.clone();
        let receiver = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                receiver_metrics.record_received();
                receiver_metrics
                    .record_latency(message.sent_at.elapsed().as_millis() as u64)
                    .await;
            }
        });

        senders.push(tx);
        receivers.push(receiver);
    }

    let start = Instant::now();
    for sender_idx in 0..NUM_AGENTS {
        for _ in 0..MESSAGES_PER_AGENT {
            let message = LocalMessage {
                sent_at: Instant::now(),
            };

            for (receiver_idx, tx) in senders.iter().enumerate() {
                if receiver_idx != sender_idx {
                    tx.send(message)?;
                    metrics.record_sent();
                }
            }
        }

        tokio::task::yield_now().await;
    }

    drop(senders);
    for receiver in receivers {
        receiver.await?;
    }

    let elapsed = start.elapsed();

    let summary = metrics.summary().await;
    let expected_deliveries = (NUM_AGENTS * MESSAGES_PER_AGENT * (NUM_AGENTS - 1)) as u64;
    let throughput = summary.messages_received as f64 / elapsed.as_secs_f64().max(f64::EPSILON);

    println!("=== Message Throughput (local pub/sub) ===");
    println!("Messages sent: {}", summary.messages_sent);
    println!("Messages received: {}", summary.messages_received);
    println!("Throughput: {:.2} msg/s", throughput);
    println!("p95 latency: {:.2}ms", summary.p95_latency_ms);

    assert_eq!(summary.messages_sent, expected_deliveries);
    assert_eq!(summary.messages_received, expected_deliveries);
    assert!(
        throughput >= MIN_LOCAL_THROUGHPUT_MSGS_PER_SEC,
        "Throughput should be >= {} msg/s, was {:.2} msg/s over {:?}",
        MIN_LOCAL_THROUGHPUT_MSGS_PER_SEC,
        throughput,
        elapsed
    );
    assert!(
        summary.p95_latency_ms <= MAX_LOCAL_P95_LATENCY_MS,
        "p95 latency should be <= {}ms, was {:.2}ms",
        MAX_LOCAL_P95_LATENCY_MS,
        summary.p95_latency_ms
    );

    Ok(())
}

/// Test 3: Convergence latency with network partitions
#[tokio::test]
async fn test_convergence_with_partitions() -> CrdtResult<()> {
    // Simulate 2 groups, partition, operations, heal, measure convergence
    let list_id = TaskListId::new([2u8; 32]);

    let mut group_a: Vec<TaskList> = (0..5)
        .map(|i| TaskList::new(list_id, "Partition Test".to_string(), peer_id(i)))
        .collect();

    let mut group_b: Vec<TaskList> = (5..10)
        .map(|i| TaskList::new(list_id, "Partition Test".to_string(), peer_id(i)))
        .collect();

    // Group A adds tasks 0-4
    for (i, replica) in group_a.iter_mut().enumerate() {
        add_scale_task(replica, i, 0, "GroupA")?;
    }

    // Group B adds tasks 5-9
    for (i, replica) in group_b.iter_mut().enumerate() {
        add_scale_task(replica, i + 5, 0, "GroupB")?;
    }

    let partition_metrics = Metrics::new();
    merge_full_mesh(&mut group_a, &partition_metrics)?;
    merge_full_mesh(&mut group_b, &partition_metrics)?;

    // Measure heal time
    let start = Instant::now();

    // Merge groups
    for replica_a in &mut group_a {
        for replica_b in &group_b {
            replica_a.merge(replica_b)?;
        }
    }
    for replica_b in &mut group_b {
        for replica_a in &group_a {
            replica_b.merge(replica_a)?;
        }
    }

    let heal_time = start.elapsed();

    // Verify all replicas have 10 tasks
    for replica in group_a.iter().chain(group_b.iter()) {
        assert_eq!(
            replica.tasks_ordered().len(),
            10,
            "Should have 10 tasks after heal"
        );
    }

    println!("Partition heal time: {:?}", heal_time);
    assert!(
        heal_time < Duration::from_millis(100),
        "Partition heal should be < 100ms"
    );

    Ok(())
}

/// Test 4: Stress test - 100 local agents
#[tokio::test]
async fn test_stress_100_agents() -> CrdtResult<()> {
    const NUM_AGENTS: usize = 100;
    const TASKS_PER_AGENT: usize = 1;

    let metrics = Metrics::new();
    let list_id = TaskListId::new([3u8; 32]);
    let mut replicas: Vec<TaskList> = (0..NUM_AGENTS)
        .map(|i| TaskList::new(list_id, "100 Agent Stress".to_string(), peer_id(i as u8)))
        .collect();

    let start = Instant::now();
    for (i, replica) in replicas.iter_mut().enumerate() {
        for j in 0..TASKS_PER_AGENT {
            add_scale_task(replica, i, j, "Stress")?;
            metrics.record_sent();
        }
    }

    merge_full_mesh(&mut replicas, &metrics)?;
    let convergence_time = start.elapsed();
    metrics
        .record_convergence(convergence_time.as_millis() as u64)
        .await;

    let expected_tasks = NUM_AGENTS * TASKS_PER_AGENT;
    for replica in &replicas {
        assert_eq!(
            replica.tasks_ordered().len(),
            expected_tasks,
            "All 100 replicas should converge to {} tasks",
            expected_tasks
        );
    }

    let summary = metrics.summary().await;
    println!("=== CRDT Stress (100 agents) ===");
    println!("Convergence time: {:?}", convergence_time);
    println!("Messages sent: {}", summary.messages_sent);
    println!("Messages received: {}", summary.messages_received);
    println!("p95 convergence: {:.2}ms", summary.p95_convergence_ms);

    assert_eq!(summary.messages_sent, expected_tasks as u64);
    assert_eq!(summary.messages_received, (NUM_AGENTS * NUM_AGENTS) as u64);
    assert!(
        convergence_time < Duration::from_secs(15),
        "100-agent local convergence should be < 15s, was {:?}",
        convergence_time
    );

    Ok(())
}
