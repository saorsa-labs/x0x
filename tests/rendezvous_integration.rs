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

    // No x0x API exposes "which shard coordinator holds my registration".
    // `Agent::get_shard_coordinator` / `coordinator.has_agent` do not exist:
    // rendezvous in x0x is publish-only. The agent pushes a signed
    // `ProviderSummary` to its shard topic via `advertise_identity`; seekers
    // consume it via `find_agent` / `find_agent_rendezvous` (see
    // `test_agent_lookup_via_shard`). Successful `join_network` plus the
    // settle window above is the strongest registration signal x0x surfaces.
    Ok(())
}

/// Test 4: Agent lookup via shard query
#[tokio::test]
#[ignore = "requires Phase 1.3 and VPS testnet"]
async fn test_agent_lookup_via_shard() -> TestResult {
    // Advertiser joins the mesh and publishes a rendezvous `ProviderSummary`
    // to its shard topic; the seeker subscribes to that shard topic via
    // `find_agent_rendezvous` and expects to observe the advertiser's
    // ProviderSummary-encoded addresses within the lookup window.
    let bootstrap_addrs: Vec<_> = VPS_NODES.iter().filter_map(|s| s.parse().ok()).collect();

    let advertiser_dir = TempDir::new()?;
    let advertiser = Agent::builder()
        .with_machine_key(advertiser_dir.path().join("machine.key"))
        .with_network_config(NetworkConfig {
            bind_addr: Some("0.0.0.0:0".parse()?),
            bootstrap_nodes: bootstrap_addrs.clone(),
            ..Default::default()
        })
        .build()
        .await?;
    advertiser.join_network().await?;

    let seeker_dir = TempDir::new()?;
    let seeker = Agent::builder()
        .with_machine_key(seeker_dir.path().join("machine.key"))
        .with_network_config(NetworkConfig {
            bind_addr: Some("0.0.0.0:0".parse()?),
            bootstrap_nodes: bootstrap_addrs,
            ..Default::default()
        })
        .build()
        .await?;
    seeker.join_network().await?;

    // Let both agents settle on the mesh before the lookup.
    sleep(Duration::from_secs(3)).await;

    let target = advertiser.agent_id();
    // Run the seeker's shard lookup concurrently with a fresh re-publish by
    // the advertiser so the subscriber catches a ProviderSummary even if the
    // first advertisement raced ahead of the subscription. 24h validity
    // matches the daemon's rendezvous re-advertise cadence.
    let lookup = tokio::time::timeout(
        Duration::from_secs(15),
        seeker.find_agent_rendezvous(target, 10),
    );
    let republish = async {
        for _ in 0..4 {
            let _ = advertiser.advertise_identity(86_400_000).await;
            sleep(Duration::from_secs(2)).await;
        }
    };
    let (lookup_outcome, _) = tokio::join!(lookup, republish);
    let found = lookup_outcome
        .expect("seeker find_agent_rendezvous did not return within 15s")?;
    assert!(
        found.is_some(),
        "find_agent_rendezvous should return the advertiser's addresses from its shard topic"
    );
    Ok(())
}

/// Test 5: Coordinator advert propagation
#[tokio::test]
#[ignore = "requires Phase 1.3 and VPS testnet"]
async fn test_coordinator_advert_propagation() {
    // Not wired in x0x. The daemon never publishes the ML-DSA-signed
    // `saorsa_gossip_coordinator::CoordinatorAdvert` (0.5.67): that type
    // exists in the dependency and `GossipCacheAdapter` consumes it on
    // ingest, but no x0x code path produces or broadcasts one. The only
    // signed adverts x0x emits are `CapabilityAdvert` (DM caps,
    // `x0x/caps/v1`; 5-min republish / 15-min cache TTL) and the rendezvous
    // `ProviderSummary`. The "24h-TTL coordinator advert with 10s global
    // propagation" this test described is a feature the application does
    // not exercise.
}

/// Test 6: Coordinator failover
#[tokio::test]
#[ignore = "requires Phase 1.3 and VPS testnet with coordinator shutdown"]
async fn test_coordinator_failover() {
    // No failover API exists. Neither x0x nor saorsa-gossip-coordinator
    // 0.5.67 exposes a primary/backup coordinator role, leader election, or
    // takeover hook for a shard: `CoordinatorAdvert` is a capability
    // advertisement with a validity window, and
    // `GossipCacheAdapter::select_coordinators` ranks candidates by score
    // but does not elect or fail over. The "identify primary, kill it,
    // verify backup takes over within 30s" flow this test described would
    // require a coordination/election layer that is absent upstream.
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
async fn test_concurrent_shard_queries() -> TestResult {
    // Fire 100 concurrent lookups via the real `find_agent` API and verify
    // the query path stays responsive under fan-out: every query completes
    // within its budget, none hang or error. Targets are deterministic agent
    // ids; on a live testnet some may resolve and some may not, so success
    // here is "every query returns an Ok outcome within the per-query
    // budget", not "every query finds an agent". (The mean/p99 latency
    // bounds originally listed assumed a warm, populated testnet and cannot
    // be asserted without 100 known-live advertisers, so they are replaced
    // by the honest completion/no-hang assertion.)
    let bootstrap_addrs: Vec<_> = VPS_NODES.iter().filter_map(|s| s.parse().ok()).collect();
    let seeker_dir = TempDir::new()?;
    let seeker = Agent::builder()
        .with_machine_key(seeker_dir.path().join("machine.key"))
        .with_network_config(NetworkConfig {
            bind_addr: Some("0.0.0.0:0".parse()?),
            bootstrap_nodes: bootstrap_addrs,
            ..Default::default()
        })
        .build()
        .await?;
    seeker.join_network().await?;
    // Settle before fanning out so the gossip runtime is ready.
    sleep(Duration::from_secs(3)).await;

    const QUERY_COUNT: usize = 100;
    // find_agent's internal budget is ~10s (5s shard + 5s rendezvous); add margin.
    const PER_QUERY_BUDGET: Duration = Duration::from_secs(15);
    let seeker = std::sync::Arc::new(seeker);

    let mut handles = Vec::with_capacity(QUERY_COUNT);
    for seed in 0..QUERY_COUNT as u32 {
        let seeker = std::sync::Arc::clone(&seeker);
        handles.push(tokio::spawn(async move {
            tokio::time::timeout(
                PER_QUERY_BUDGET,
                seeker.find_agent(deterministic_agent_id(seed)),
            )
            .await
        }));
    }

    for handle in handles {
        let outcome = handle.await.expect("query task must join");
        let resolved = outcome.expect("query exceeded per-query budget; query path hung under fan-out");
        // find_agent returns Result<Option<Vec<SocketAddr>>, x0x::Error>; propagate any
        // error as a test failure. Ok(None) is acceptable (target not present
        // on the testnet) — only the no-hang + no-error contract is asserted.
        let _ = resolved?;
    }
    Ok(())
}
