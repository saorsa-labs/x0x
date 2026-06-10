//! Rendezvous Shard Discovery Integration Tests
//!
//! Verifies rendezvous sharding for global agent findability across 65,536
//! content-addressed shards.
//!
//! Offline shard-computation invariants run by default. Live VPS rendezvous
//! propagation tests remain explicitly ignored because they require the testnet.

use std::{error::Error, time::Duration};
use tempfile::TempDir;
use tokio::time::sleep;
use x0x::{identity::AgentId, network::NetworkConfig, Agent};

/// VPS nodes
const VPS_NODES: &[&str] = &[
    "142.93.199.50:5483",
    "147.182.234.192:5483",
    "65.21.157.229:5483",
    "116.203.101.172:5483",
    "152.42.210.67:5483",
    "170.64.176.102:5483",
];

const RENDEZVOUS_TOPIC_PREFIX: &str = "x0x.rendezvous.shard.";
const SHARD_COUNT: usize = 65_536;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn expected_shard(agent_id: &AgentId) -> u16 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"saorsa-rendezvous");
    hasher.update(agent_id.as_bytes());
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    (value & 0xFFFF) as u16
}

fn rendezvous_shard(agent_id: &AgentId) -> TestResult<u16> {
    let topic = x0x::rendezvous_shard_topic_for_agent(agent_id);
    let suffix = topic
        .strip_prefix(RENDEZVOUS_TOPIC_PREFIX)
        .ok_or_else(|| std::io::Error::other(format!("invalid rendezvous topic: {topic}")))?;
    Ok(suffix.parse()?)
}

fn deterministic_agent_id(seed: u32) -> AgentId {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&seed.to_le_bytes());
    id[4..8].copy_from_slice(&seed.rotate_left(13).to_le_bytes());
    id[8..12].copy_from_slice(&(!seed).to_le_bytes());
    id[12..16].copy_from_slice(&seed.wrapping_mul(0x9E37_79B9).to_le_bytes());
    AgentId(id)
}

fn incrementing_agent_id() -> AgentId {
    AgentId(std::array::from_fn(|i| i as u8))
}

/// Test 1: Shard assignment determinism
///
/// Verifies that ShardId = BLAKE3("saorsa-rendezvous" || agent_id) & 0xFFFF
/// produces deterministic, collision-resistant shard assignments.
#[test]
fn test_shard_assignment_deterministic() -> TestResult {
    let vectors = [
        (AgentId([0x00; 32]), 61_660),
        (AgentId([0x01; 32]), 37_986),
        (AgentId([0xFF; 32]), 57_388),
        (AgentId([0x2A; 32]), 31_048),
        (incrementing_agent_id(), 20_774),
    ];

    for (agent_id, expected) in vectors {
        let shard_a = rendezvous_shard(&agent_id)?;
        let shard_b = rendezvous_shard(&agent_id)?;
        assert_eq!(
            shard_a, shard_b,
            "rendezvous shard assignment must be deterministic"
        );
        assert_eq!(
            shard_a, expected,
            "rendezvous shard must match the stable test vector"
        );
        assert_eq!(
            shard_a,
            expected_shard(&agent_id),
            "rendezvous shard must follow the BLAKE3 domain-separated formula"
        );
    }

    Ok(())
}

/// Test 2: Shard collision resistance
///
/// Verifies that 10,000 deterministic agent IDs have an occupancy profile
/// consistent with uniform hashing. With 65,536 shards the expected per-shard
/// load is only 0.15, so this checks occupancy and hot-shard bounds instead of
/// an impossible per-shard percentage deviation.
#[test]
fn test_shard_collision_resistance() -> TestResult {
    const SAMPLE_COUNT: u32 = 10_000;
    // Uniform hashing expects about 9,274 occupied shards for this sample size.
    const MIN_OCCUPIED_SHARDS: usize = 9_000;
    const MAX_OCCUPIED_SHARDS: usize = 9_600;
    const MAX_SHARD_LOAD: u16 = 6;

    let mut counts = vec![0u16; SHARD_COUNT];

    for seed in 0..SAMPLE_COUNT {
        let shard = rendezvous_shard(&deterministic_agent_id(seed))? as usize;
        counts[shard] += 1;
    }

    let occupied = counts.iter().filter(|count| **count > 0).count();
    let max_count = counts.iter().copied().max().unwrap_or(0);
    let collisions = SAMPLE_COUNT as usize - occupied;

    assert!(
        (MIN_OCCUPIED_SHARDS..=MAX_OCCUPIED_SHARDS).contains(&occupied),
        "10,000 agent IDs should occupy {MIN_OCCUPIED_SHARDS}..={MAX_OCCUPIED_SHARDS} shards, got {occupied} ({collisions} collisions)"
    );
    assert!(
        max_count <= MAX_SHARD_LOAD,
        "no shard should receive more than {MAX_SHARD_LOAD} of 10,000 deterministic IDs, got {max_count}"
    );

    Ok(())
}

/// Test 3: Agent registration to correct shard coordinator
#[tokio::test]
#[ignore = "requires Phase 1.3 and VPS testnet"]
async fn test_agent_registers_to_shard() -> TestResult {
    let temp_dir = TempDir::new()?;
    let bootstrap_addrs = VPS_NODES.iter().filter_map(|s| s.parse().ok()).collect();

    let agent = Agent::builder()
        .with_machine_key(temp_dir.path().join("machine.key"))
        .with_network_config(NetworkConfig {
            bind_addr: Some("0.0.0.0:0".parse()?),
            bootstrap_nodes: bootstrap_addrs,
            ..Default::default()
        })
        .build()
        .await?;

    agent.join_network().await?;
    sleep(Duration::from_secs(5)).await;

    // TODO: Verify agent registered to correct shard coordinator
    // let shard_id = compute_shard_id(&agent.agent_id());
    // let coordinator = agent.get_shard_coordinator(shard_id).await?;
    // assert!(coordinator.has_agent(&agent.agent_id()));
    Ok(())
}

/// Test 4: Agent lookup via shard query
#[tokio::test]
#[ignore = "requires Phase 1.3 and VPS testnet"]
async fn test_agent_lookup_via_shard() {
    // TODO: Create 2 agents
    // TODO: Agent A queries shard for Agent B
    // Expected: Query returns Agent B's network address
    // Expected: Query latency < 1 second
}

/// Test 5: Coordinator advert propagation
#[tokio::test]
#[ignore = "requires Phase 1.3 and VPS testnet"]
async fn test_coordinator_advert_propagation() {
    // TODO: VPS nodes should advertise as coordinators
    // TODO: Verify ML-DSA signed adverts propagate globally
    // Expected: All 6 VPS nodes advertise as coordinators
    // Expected: Adverts have 24h TTL
    // Expected: Adverts propagate within 10 seconds
}

/// Test 6: Coordinator failover
#[tokio::test]
#[ignore = "requires Phase 1.3 and VPS testnet with coordinator shutdown"]
async fn test_coordinator_failover() {
    // TODO: Identify primary coordinator for a shard
    // TODO: Simulate coordinator going offline
    // TODO: Verify backup coordinator takes over
    // Expected: Failover within 30 seconds
    // Expected: No data loss during failover
}

/// Test 7: Shard load balancing
#[test]
fn test_shard_load_balancing() -> TestResult {
    const SAMPLE_COUNT: u32 = 100_000;
    const BUCKET_COUNT: usize = 256;
    const MAX_SHARD_LOAD: u16 = 12;
    // 255 degrees of freedom; loose 99.9% upper-tail bound for bucket uniformity.
    const CHI_SQUARED_999_UPPER_BOUND: f64 = 340.0;

    let mut shard_counts = vec![0u16; SHARD_COUNT];
    let mut bucket_counts = [0u32; BUCKET_COUNT];

    for seed in 0..SAMPLE_COUNT {
        let shard = rendezvous_shard(&deterministic_agent_id(seed))? as usize;
        shard_counts[shard] += 1;
        bucket_counts[shard / BUCKET_COUNT] += 1;
    }

    let max_shard_count = shard_counts.iter().copied().max().unwrap_or(0);
    let expected_per_bucket = f64::from(SAMPLE_COUNT) / BUCKET_COUNT as f64;
    let chi_squared = bucket_counts
        .iter()
        .map(|count| {
            let deviation = f64::from(*count) - expected_per_bucket;
            deviation * deviation / expected_per_bucket
        })
        .sum::<f64>();

    assert!(
        max_shard_count <= MAX_SHARD_LOAD,
        "no shard should receive more than {MAX_SHARD_LOAD} of 100,000 deterministic IDs, got {max_shard_count}"
    );
    assert!(
        chi_squared <= CHI_SQUARED_999_UPPER_BOUND,
        "256 coarse buckets should pass chi-squared uniformity check; statistic {chi_squared:.2}, bound {CHI_SQUARED_999_UPPER_BOUND:.2}"
    );

    Ok(())
}

/// Test 8: Concurrent shard queries
#[tokio::test]
#[ignore = "requires Phase 1.3 and VPS testnet"]
async fn test_concurrent_shard_queries() {
    // TODO: Launch 100 concurrent shard queries
    // TODO: Verify all queries succeed
    // Expected: No query timeouts
    // Expected: Mean latency < 500ms
    // Expected: p99 latency < 2s
}
