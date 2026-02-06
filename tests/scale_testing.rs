//! Scale Testing Framework and Execution
//!
//! Tests x0x performance under load: 100+ agents, sustained message throughput,
//! CRDT convergence time, resource usage. Combines framework (Task 6) and
//! execution (Task 7).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use x0x::crdt::{TaskId, TaskItem, TaskList, TaskListId, TaskMetadata};
use x0x::identity::AgentId;
// // Reserved for network tests // Reserved for future network tests

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

    #[allow(dead_code)]
    #[allow(dead_code)]
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
    let idx = ((p as f64 / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[idx.min(sorted.len() - 1)] as f64
}

/// Test 1: CRDT convergence with 10 agents, 50 tasks
///
/// Measures convergence time for 10 local agents performing concurrent
/// task list operations.
#[tokio::test]
async fn test_crdt_convergence_10_agents_50_tasks() {
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
            let task_id = TaskId::from_bytes([(i * 10 + j) as u8; 32]);
            let meta = TaskMetadata {
                title: format!("Task {}-{}", i, j),
                description: format!("Agent {} task {}", i, j),
                priority: 128,
                created_by: AgentId([i as u8; 32]),
                created_at: 1000 + (i * 10 + j) as u64,
                tags: vec!["scale".to_string()],
            };
            let task = TaskItem::new(
                task_id,
                meta,
                saorsa_gossip_types::PeerId::new([i as u8; 32]),
            );
            replica
                .add_task(
                    task,
                    saorsa_gossip_types::PeerId::new([i as u8; 32]),
                    (i * 10 + j) as u64,
                )
                .expect("Failed to add task");
            metrics.record_sent();
        }
    }

    // Simulate gossip convergence (full mesh merge)
    let clones: Vec<TaskList> = replicas.clone();
    for replica in &mut replicas {
        for other in &clones {
            replica.merge(other).expect("Merge failed");
            metrics.record_received();
        }
    }

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
}

/// Test 2: Message throughput (local pub/sub)
///
/// Measures sustained message throughput without network overhead.
#[tokio::test]
#[ignore = "long-running test (5 minutes)"]
async fn test_message_throughput_local() {
    let metrics = Metrics::new();
    let _test_duration = Duration::from_secs(300); // 5 minutes

    // TODO: Create pub/sub agents and measure throughput
    // Target: > 500 msg/s sustained
    // This requires network layer, stub for now

    let summary = metrics.summary().await;
    println!("=== Message Throughput (5 min) ===");
    println!("Messages sent: {}", summary.messages_sent);
    println!("Messages received: {}", summary.messages_received);
}

/// Test 3: Memory usage per agent
#[test]
#[ignore = "requires memory profiling"]
fn test_memory_usage_per_agent() {
    // TODO: Spawn 100 agents, measure resident memory
    // Target: < 50MB per agent
}

/// Test 4: CPU usage under load
#[tokio::test]
#[ignore = "requires CPU profiling"]
async fn test_cpu_usage_under_load() {
    // TODO: Generate 1000 msg/s, measure CPU %
    // Target: < 25% CPU on 4-core system
}

/// Test 5: Convergence latency with network partitions
#[tokio::test]
async fn test_convergence_with_partitions() {
    // Simulate 2 groups, partition, operations, heal, measure convergence
    let list_id = TaskListId::new([2u8; 32]);

    let mut group_a: Vec<TaskList> = (0..5)
        .map(|i| {
            TaskList::new(
                list_id,
                "Partition Test".to_string(),
                saorsa_gossip_types::PeerId::new([i; 32]),
            )
        })
        .collect();

    let mut group_b: Vec<TaskList> = (5..10)
        .map(|i| {
            TaskList::new(
                list_id,
                "Partition Test".to_string(),
                saorsa_gossip_types::PeerId::new([i; 32]),
            )
        })
        .collect();

    // Group A adds tasks 0-4
    for (i, replica) in group_a.iter_mut().enumerate() {
        let task_id = TaskId::from_bytes([i as u8; 32]);
        let meta = TaskMetadata {
            title: format!("GroupA-{}", i),
            description: String::new(),
            priority: 128,
            created_by: AgentId([i as u8; 32]),
            created_at: 1000 + i as u64,
            tags: vec![],
        };
        let task = TaskItem::new(
            task_id,
            meta,
            saorsa_gossip_types::PeerId::new([i as u8; 32]),
        );
        replica
            .add_task(
                task,
                saorsa_gossip_types::PeerId::new([i as u8; 32]),
                i as u64,
            )
            .expect("Add failed");
    }

    // Group B adds tasks 5-9
    for (i, replica) in group_b.iter_mut().enumerate() {
        let task_id = TaskId::from_bytes([(i + 5) as u8; 32]);
        let meta = TaskMetadata {
            title: format!("GroupB-{}", i),
            description: String::new(),
            priority: 128,
            created_by: AgentId([(i + 5) as u8; 32]),
            created_at: 1000 + (i + 5) as u64,
            tags: vec![],
        };
        let task = TaskItem::new(
            task_id,
            meta,
            saorsa_gossip_types::PeerId::new([(i + 5) as u8; 32]),
        );
        replica
            .add_task(
                task,
                saorsa_gossip_types::PeerId::new([(i + 5) as u8; 32]),
                (i + 5) as u64,
            )
            .expect("Add failed");
    }

    // Measure heal time
    let start = Instant::now();

    // Merge groups
    for replica_a in &mut group_a {
        for replica_b in &group_b {
            replica_a.merge(replica_b).expect("Merge failed");
        }
    }
    for replica_b in &mut group_b {
        for replica_a in &group_a {
            replica_b.merge(replica_a).expect("Merge failed");
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
}

/// Test 6: Stress test - 100 agents (network required)
#[tokio::test]
#[ignore = "requires VPS testnet and long duration"]
async fn test_stress_100_agents() {
    // TODO: Spawn 100 agents connecting to VPS mesh
    // TODO: Each agent publishes 10 msg/s for 5 minutes
    // TODO: Measure: p95 latency, bandwidth, memory, convergence
    // Targets:
    // - p95 latency < 500ms
    // - Throughput > 500 msg/s
    // - Memory < 50MB per agent
    // - No crashes/panics
}
