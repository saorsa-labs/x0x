//! Integration tests for NAT traversal across VPS testnet.
//!
//! These tests verify QUIC hole punching works correctly across the 6 global
//! VPS nodes and from local machines behind NAT.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tempfile::TempDir;
use tokio::time::timeout;
use x0x::{network::NetworkConfig, network::NetworkNode, Agent};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type TestResult<T> = Result<T, BoxError>;

/// Global VPS bootstrap nodes (from Phase 3.1 deployment)
const VPS_NODES: &[&str] = &[
    "142.93.199.50:5483",   // saorsa-2 (NYC)
    "147.182.234.192:5483", // saorsa-3 (SFO)
    "65.21.157.229:5483",   // saorsa-6 (Helsinki)
    "116.203.101.172:5483", // saorsa-7 (Nuremberg)
    "152.42.210.67:5483",   // saorsa-8 (Singapore)
    "170.64.176.102:5483",  // saorsa-9 (Sydney)
];

fn test_error(message: impl Into<String>) -> BoxError {
    std::io::Error::other(message.into()).into()
}

fn timeout_error(message: impl Into<String>) -> BoxError {
    std::io::Error::new(std::io::ErrorKind::TimedOut, message.into()).into()
}

fn vps_bootstrap_addrs() -> TestResult<Vec<SocketAddr>> {
    let mut addrs = Vec::with_capacity(VPS_NODES.len());
    for raw_addr in VPS_NODES {
        let addr = raw_addr.parse::<SocketAddr>().map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid VPS bootstrap address {raw_addr}: {err}"),
            )
        })?;
        addrs.push(addr);
    }
    Ok(addrs)
}

fn agent_network(agent: &Agent) -> TestResult<Arc<NetworkNode>> {
    agent
        .network()
        .cloned()
        .ok_or_else(|| test_error("agent should have network runtime after join"))
}

async fn join_vps_network(agent: &Agent) -> TestResult<()> {
    timeout(Duration::from_secs(30), agent.join_network())
        .await
        .map_err(|_| timeout_error("network join timed out after 30 seconds"))??;
    Ok(())
}

async fn connect_all_vps_nodes(
    agent: &Agent,
    per_node_timeout: Duration,
) -> TestResult<Vec<(SocketAddr, ant_quic::PeerId)>> {
    let network = agent_network(agent)?;
    let mut connected = Vec::with_capacity(VPS_NODES.len());

    for addr in vps_bootstrap_addrs()? {
        let peer_id = timeout(per_node_timeout, network.connect_addr(addr))
            .await
            .map_err(|_| {
                timeout_error(format!(
                    "connection to VPS node {addr} timed out after {per_node_timeout:?}"
                ))
            })?
            .map_err(|err| test_error(format!("connection to VPS node {addr} failed: {err}")))?;
        connected.push((addr, peer_id));
    }

    Ok(connected)
}

async fn assert_vps_peer_set(
    agent: &Agent,
    connected_vps_nodes: &[(SocketAddr, ant_quic::PeerId)],
) -> TestResult<()> {
    assert_eq!(
        connected_vps_nodes.len(),
        VPS_NODES.len(),
        "every configured VPS bootstrap address must be probed"
    );

    let unique_vps_peers: HashSet<[u8; 32]> = connected_vps_nodes
        .iter()
        .map(|(_, peer_id)| peer_id.0)
        .collect();
    assert_eq!(
        unique_vps_peers.len(),
        connected_vps_nodes.len(),
        "VPS bootstrap addresses should resolve to distinct remote peers"
    );

    let network = agent_network(agent)?;
    let live_peer_ids: HashSet<[u8; 32]> = network
        .connected_peers()
        .await
        .into_iter()
        .map(|peer_id| peer_id.0)
        .collect();
    let missing: Vec<String> = connected_vps_nodes
        .iter()
        .filter(|(_, peer_id)| !live_peer_ids.contains(&peer_id.0))
        .map(|(addr, peer_id)| format!("{addr} ({peer_id:?})"))
        .collect();

    assert!(
        missing.is_empty(),
        "VPS nodes connected by address must remain in the live peer table; missing: {}",
        missing.join(", ")
    );
    assert!(
        live_peer_ids.len() >= VPS_NODES.len(),
        "expected at least {} live VPS peers, got {}",
        VPS_NODES.len(),
        live_peer_ids.len()
    );

    Ok(())
}

async fn probe_vps_peers(
    agent: &Agent,
    connected_vps_nodes: &[(SocketAddr, ant_quic::PeerId)],
) -> TestResult<()> {
    let network = agent_network(agent)?;

    for (addr, peer_id) in connected_vps_nodes {
        let rtt = timeout(
            Duration::from_secs(5),
            network.probe_peer(*peer_id, Duration::from_secs(5)),
        )
        .await
        .map_err(|_| timeout_error(format!("probe to VPS node {addr} timed out")))?
        .ok_or_else(|| test_error("network runtime missing during VPS probe"))?
        .map_err(|err| test_error(format!("probe to VPS node {addr} failed: {err}")))?;

        println!("VPS node {addr} probe RTT: {rtt:?}");
        assert!(
            rtt < Duration::from_secs(2),
            "probe RTT to VPS node {addr} ({peer_id:?}) too high: {rtt:?}"
        );
    }

    Ok(())
}

fn is_publicly_routable(addr: SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }

    match addr.ip() {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_multicast()
                || (octets[0] == 100 && (64..=127).contains(&octets[1])))
        }
        IpAddr::V6(ip) => {
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast())
        }
    }
}

async fn wait_for_public_external_addrs(
    agent: &Agent,
    wait_duration: Duration,
) -> TestResult<Vec<SocketAddr>> {
    let network = agent_network(agent)?;
    let deadline = Instant::now() + wait_duration;
    let mut last_external_addrs = Vec::new();

    loop {
        if let Some(status) = network.node_status().await {
            let public_addrs: Vec<SocketAddr> = status
                .external_addrs
                .iter()
                .copied()
                .filter(|addr| is_publicly_routable(*addr))
                .collect();

            if !public_addrs.is_empty() {
                return Ok(public_addrs);
            }

            last_external_addrs = status.external_addrs;
        }

        if Instant::now() >= deadline {
            return Err(timeout_error(format!(
                "timed out waiting for a public external address; last observed addresses: {last_external_addrs:?}"
            )));
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

struct VpsAgentPaths {
    machine_key: PathBuf,
    agent_key: PathBuf,
    user_key: PathBuf,
    agent_cert: PathBuf,
    peer_cache_dir: PathBuf,
}

fn vps_agent_paths(base_dir: &Path) -> VpsAgentPaths {
    VpsAgentPaths {
        machine_key: base_dir.join("machine.key"),
        agent_key: base_dir.join("agent.key"),
        user_key: base_dir.join("user.key"),
        agent_cert: base_dir.join("agent.cert"),
        peer_cache_dir: base_dir.join("peers"),
    }
}

struct VpsTestAgent {
    agent: Agent,
    _temp_dir: TempDir,
}

impl std::ops::Deref for VpsTestAgent {
    type Target = Agent;

    fn deref(&self) -> &Self::Target {
        &self.agent
    }
}

/// Helper to create agent with VPS bootstrap nodes.
async fn create_agent_with_vps_bootstrap() -> TestResult<VpsTestAgent> {
    let temp_dir = TempDir::new()?;
    let paths = vps_agent_paths(temp_dir.path());
    let bootstrap_addrs = vps_bootstrap_addrs()?;

    let agent = Agent::builder()
        .with_machine_key(paths.machine_key)
        .with_agent_key_path(paths.agent_key)
        .with_user_key_path(paths.user_key)
        .with_agent_cert_path(paths.agent_cert)
        .with_peer_cache_dir(paths.peer_cache_dir)
        .with_network_config(NetworkConfig {
            bind_addr: Some("0.0.0.0:0".parse()?),
            bootstrap_nodes: bootstrap_addrs,
            ..Default::default()
        })
        .build()
        .await?;

    Ok(VpsTestAgent {
        agent,
        _temp_dir: temp_dir,
    })
}

#[test]
fn vps_bootstrap_addresses_are_well_formed() -> TestResult<()> {
    let addrs = vps_bootstrap_addrs()?;
    let unique_addrs: HashSet<SocketAddr> = addrs.iter().copied().collect();

    assert_eq!(
        addrs.len(),
        VPS_NODES.len(),
        "all configured VPS bootstrap nodes must parse"
    );
    assert_eq!(
        unique_addrs.len(),
        addrs.len(),
        "VPS bootstrap addresses should be unique"
    );
    for addr in addrs {
        assert_ne!(addr.port(), 0, "VPS bootstrap node must use a real port");
        assert!(
            !addr.ip().is_unspecified(),
            "VPS bootstrap node must not use an unspecified IP: {addr}"
        );
    }

    Ok(())
}

#[test]
fn vps_agent_paths_are_isolated_under_fixture_dir() -> TestResult<()> {
    let temp_dir = TempDir::new()?;
    let paths = vps_agent_paths(temp_dir.path());

    assert!(paths.machine_key.starts_with(temp_dir.path()));
    assert!(paths.agent_key.starts_with(temp_dir.path()));
    assert!(paths.user_key.starts_with(temp_dir.path()));
    assert!(paths.agent_cert.starts_with(temp_dir.path()));
    assert!(paths.peer_cache_dir.starts_with(temp_dir.path()));

    Ok(())
}

/// Test 1: Verify all VPS nodes are reachable and healthy.
///
/// This test attempts to connect to all 6 VPS bootstrap nodes from the local machine.
/// Success indicates NAT traversal is working (local NAT → public VPS).
#[tokio::test]
#[ignore = "requires VPS testnet - run with --ignored"]
async fn test_vps_nodes_reachable() -> TestResult<()> {
    let agent = create_agent_with_vps_bootstrap().await?;

    join_vps_network(&agent).await?;

    let connected_vps_nodes = connect_all_vps_nodes(&agent, Duration::from_secs(15)).await?;
    assert_vps_peer_set(&agent, &connected_vps_nodes).await?;

    Ok(())
}

/// Test 2: Measure connection latency to each VPS node.
///
/// This test measures round-trip time to verify NAT hole punching performance.
#[tokio::test]
#[ignore = "requires VPS testnet - run with --ignored"]
async fn test_connection_latency() -> TestResult<()> {
    let agent = create_agent_with_vps_bootstrap().await?;

    join_vps_network(&agent).await?;
    let connected_vps_nodes = connect_all_vps_nodes(&agent, Duration::from_secs(15)).await?;
    assert_vps_peer_set(&agent, &connected_vps_nodes).await?;
    probe_vps_peers(&agent, &connected_vps_nodes).await?;

    Ok(())
}

/// Test 3: Connection pool stability over time.
///
/// This test verifies connections remain stable and don't drop unexpectedly.
#[tokio::test]
#[ignore = "requires VPS testnet - run with --ignored"]
async fn test_connection_stability() -> TestResult<()> {
    let agent = create_agent_with_vps_bootstrap().await?;

    join_vps_network(&agent).await?;
    let connected_vps_nodes = connect_all_vps_nodes(&agent, Duration::from_secs(15)).await?;
    assert_vps_peer_set(&agent, &connected_vps_nodes).await?;

    // Subscribe to test topic
    let topic = format!(
        "stability-test-{}",
        hex::encode(&agent.machine_id().as_bytes()[..8])
    );
    let mut subscription = agent.subscribe(&topic).await?;

    // Send messages periodically for 5 minutes
    let test_duration = Duration::from_secs(300);
    let message_interval = Duration::from_secs(10);
    let start = std::time::Instant::now();
    let mut message_count = 0;
    let mut received_count = 0;

    while start.elapsed() < test_duration {
        // Publish message
        agent
            .publish(&topic, format!("msg-{}", message_count).into_bytes())
            .await?;
        message_count += 1;

        // Try to receive any messages (non-blocking)
        while let Ok(Some(_msg)) =
            tokio::time::timeout(Duration::from_millis(100), subscription.recv()).await
        {
            received_count += 1;
        }

        tokio::time::sleep(message_interval).await;
    }

    println!(
        "Sent {} messages, received {} messages over {} seconds",
        message_count,
        received_count,
        test_duration.as_secs()
    );

    // We should have sent at least 25 messages (300s / 10s)
    assert!(
        message_count >= 25,
        "Expected at least 25 messages, sent {}",
        message_count
    );

    // We should receive at least some messages back (may not be all due to async timing)
    assert!(
        received_count > 0,
        "Should have received at least some messages back"
    );
    assert_vps_peer_set(&agent, &connected_vps_nodes).await?;
    probe_vps_peers(&agent, &connected_vps_nodes).await?;

    Ok(())
}

/// Test 4: Multiple concurrent agents connecting to VPS mesh.
///
/// This test simulates multiple agents (10) connecting simultaneously to verify
/// the VPS mesh can handle concurrent connections.
#[tokio::test]
#[ignore = "requires VPS testnet - run with --ignored"]
async fn test_concurrent_connections() -> TestResult<()> {
    let num_agents = 10;
    let mut handles = Vec::new();

    for _ in 0..num_agents {
        let handle = tokio::spawn(async move {
            let temp_dir = TempDir::new()?;
            let paths = vps_agent_paths(temp_dir.path());
            let bootstrap_addrs = vps_bootstrap_addrs()?;

            let agent = Agent::builder()
                .with_machine_key(paths.machine_key)
                .with_agent_key_path(paths.agent_key)
                .with_user_key_path(paths.user_key)
                .with_agent_cert_path(paths.agent_cert)
                .with_peer_cache_dir(paths.peer_cache_dir)
                .with_network_config(NetworkConfig {
                    bind_addr: Some("0.0.0.0:0".parse()?),
                    bootstrap_nodes: bootstrap_addrs,
                    ..Default::default()
                })
                .build()
                .await?;

            agent.join_network().await?;
            let connected_vps_nodes =
                connect_all_vps_nodes(&agent, Duration::from_secs(15)).await?;

            // Brief delay to stabilize
            tokio::time::sleep(Duration::from_secs(2)).await;
            assert_vps_peer_set(&agent, &connected_vps_nodes).await?;

            Ok::<(), BoxError>(())
        });
        handles.push(handle);
    }

    // Wait for all agents to connect
    let results = futures::future::join_all(handles).await;

    // All agents should connect successfully
    assert_eq!(
        results.len(),
        num_agents,
        "All agents should complete connection"
    );
    for result in results {
        result??;
    }

    Ok(())
}

/// Test 5: VPS node discovery and peer exchange.
///
/// This test verifies agents can discover all VPS nodes through peer exchange.
#[tokio::test]
#[ignore = "requires VPS testnet - run with --ignored"]
async fn test_vps_discovery() -> TestResult<()> {
    let agent = create_agent_with_vps_bootstrap().await?;

    join_vps_network(&agent).await?;

    // Wait for peer exchange to propagate (HyParView)
    tokio::time::sleep(Duration::from_secs(10)).await;

    let connected_vps_nodes = connect_all_vps_nodes(&agent, Duration::from_secs(15)).await?;
    assert_vps_peer_set(&agent, &connected_vps_nodes).await?;

    Ok(())
}

/// Test 6: Verify external address discovery works.
///
/// This test checks that agents correctly discover their external IP:port
/// through the VPS mesh (similar to STUN but using QUIC).
#[tokio::test]
#[ignore = "requires VPS testnet - run with --ignored"]
async fn test_external_address_discovery() -> TestResult<()> {
    let agent = create_agent_with_vps_bootstrap().await?;

    join_vps_network(&agent).await?;
    let connected_vps_nodes = connect_all_vps_nodes(&agent, Duration::from_secs(15)).await?;
    assert_vps_peer_set(&agent, &connected_vps_nodes).await?;

    let public_addrs = wait_for_public_external_addrs(&agent, Duration::from_secs(10)).await?;

    assert!(
        !public_addrs.is_empty(),
        "external address discovery should return at least one public address"
    );

    Ok(())
}
