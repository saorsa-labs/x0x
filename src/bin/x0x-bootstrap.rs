//! x0x bootstrap node
//!
//! A coordinator/reflector node for the x0x network that provides:
//! - Network bootstrap endpoints for new agents
//! - Rendezvous coordination
//! - Relay services for NAT traversal
//! - Health monitoring endpoint

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::signal;
use x0x::network::NetworkConfig;
use x0x::upgrade::manifest::RELEASE_TOPIC;
use x0x::upgrade::monitor::UpgradeMonitor;
use x0x::Agent;

/// Configuration for the bootstrap node
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BootstrapConfig {
    /// Address to bind the QUIC transport (e.g., "0.0.0.0:12000")
    bind_address: SocketAddr,

    /// Health endpoint address (e.g., "127.0.0.1:12600")
    health_address: SocketAddr,

    /// Path to machine keypair (defaults to /var/lib/x0x/machine.key)
    #[serde(default = "default_machine_key_path")]
    machine_key_path: PathBuf,

    /// Data directory for persistent storage
    #[serde(default = "default_data_dir")]
    data_dir: PathBuf,

    /// Enable coordinator role
    #[serde(default = "default_true")]
    coordinator: bool,

    /// Enable reflector role (NAT address discovery)
    #[serde(default = "default_true")]
    reflector: bool,

    /// Enable relay role (MASQUE relay for symmetric NAT)
    #[serde(default = "default_true")]
    relay: bool,

    /// Known peer addresses to connect on startup
    #[serde(default)]
    known_peers: Vec<SocketAddr>,

    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    log_level: String,

    /// Log format ("text" or "json")
    #[serde(default = "default_log_format")]
    log_format: String,

    /// Update configuration
    #[serde(default)]
    update: UpdateConfig,
}

/// Update configuration for x0x-bootstrap.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpdateConfig {
    /// Enable self-update checks.
    #[serde(default = "default_true")]
    enabled: bool,

    /// Check interval in seconds (default: 21600 = 6 hours).
    #[serde(default = "default_check_interval_seconds")]
    check_interval_seconds: u64,

    /// Rollout window in minutes (default: 120 = 2 hours, only 6 bootstrap nodes).
    #[serde(default = "default_rollout_window_minutes")]
    rollout_window_minutes: u64,

    /// Exit cleanly for systemd restart (default: true).
    #[serde(default = "default_true")]
    stop_on_upgrade: bool,

    /// GitHub repo for update discovery.
    #[serde(default = "default_update_repo")]
    repo: String,

    /// Include pre-releases in update checks (default: false).
    #[serde(default)]
    include_prereleases: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_seconds: 3600,
            rollout_window_minutes: 120,
            stop_on_upgrade: true,
            repo: default_update_repo(),
            include_prereleases: false,
        }
    }
}

fn default_check_interval_seconds() -> u64 {
    3600
}

fn default_rollout_window_minutes() -> u64 {
    120
}

fn default_update_repo() -> String {
    "saorsa-labs/x0x".to_string()
}

fn default_machine_key_path() -> PathBuf {
    PathBuf::from("/var/lib/x0x/machine.key")
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/x0x/data")
}

fn default_true() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            bind_address: SocketAddr::from(([0, 0, 0, 0], 12000)),
            health_address: SocketAddr::from(([127, 0, 0, 1], 12600)),
            machine_key_path: default_machine_key_path(),
            data_dir: default_data_dir(),
            coordinator: true,
            reflector: true,
            relay: true,
            known_peers: Vec::new(),
            log_level: "info".to_string(),
            log_format: "text".to_string(),
            update: UpdateConfig::default(),
        }
    }
}

/// Health check response
#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    peers: usize,
}

/// Metrics response with detailed stats
#[derive(Debug, Serialize)]
struct MetricsResponse {
    status: String,
    peers: usize,
    total_connections: u64,
    active_connections: u32,
    bytes_sent: u64,
    bytes_received: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();

    // Default config path
    let config_path = if let Some(idx) = args.iter().position(|a| a == "--config") {
        args.get(idx + 1)
            .context("--config requires a path argument")?
            .clone()
    } else {
        "/etc/x0x/bootstrap.toml".to_string()
    };

    // Check config flag (validate without running)
    let check_only = args.contains(&"--check".to_string());
    let check_updates_only = args.contains(&"--check-updates".to_string());
    let skip_update_check = args.contains(&"--skip-update-check".to_string());

    // Load configuration
    let config = load_config(&config_path).await?;

    // Initialize logging
    init_logging(&config.log_level, &config.log_format)?;

    if check_only {
        println!("Configuration is valid");
        println!("{:#?}", config);
        return Ok(());
    }

    // Startup banner
    tracing::info!(
        version = %x0x::VERSION,
        binary = "x0x-bootstrap",
        pid = std::process::id(),
        "x0x-bootstrap started"
    );
    tracing::info!("Bind address: {}", config.bind_address);
    tracing::info!("Health endpoint: {}", config.health_address);
    tracing::info!("Coordinator: {}", config.coordinator);
    tracing::info!("Reflector: {}", config.reflector);
    tracing::info!("Relay: {}", config.relay);
    tracing::info!("Known peers: {:?}", config.known_peers);

    // Startup self-update check
    if config.update.enabled && !skip_update_check {
        match run_startup_update_check(&config).await {
            Ok(true) => {
                // Update applied — binary was replaced. If stop_on_upgrade, exit for systemd restart.
                if config.update.stop_on_upgrade {
                    tracing::info!(
                        exit_code = 0,
                        "Exiting with code 0 for service manager restart"
                    );
                    std::process::exit(0);
                }
            }
            Ok(false) => {} // No update
            Err(e) => tracing::warn!(error = %e, "Startup update check failed: {e}"),
        }
    }
    if check_updates_only {
        return Ok(());
    }

    // Create data directory if it doesn't exist
    tokio::fs::create_dir_all(&config.data_dir)
        .await
        .context("failed to create data directory")?;

    // Initialize agent with network configuration
    let network_config = NetworkConfig {
        bind_addr: Some(config.bind_address),
        bootstrap_nodes: config.known_peers.clone(),
        max_connections: 100,
        connection_timeout: std::time::Duration::from_secs(30),
        stats_interval: std::time::Duration::from_secs(60),
        peer_cache_path: Some(config.data_dir.join("peers.cache")),
    };

    let agent = Arc::new(
        Agent::builder()
            .with_machine_key(&config.machine_key_path)
            .with_network_config(network_config)
            .with_peer_cache_dir(config.data_dir.join("peers"))
            .build()
            .await
            .context("failed to create agent")?,
    );

    tracing::info!("Agent initialized");
    tracing::info!("Machine ID: {}", agent.machine_id());
    tracing::info!("Agent ID: {}", agent.agent_id());

    // Join network
    agent
        .join_network()
        .await
        .context("failed to join network")?;

    tracing::info!("Network joined successfully");

    // Start health server
    let health_handle = tokio::spawn(run_health_server(
        config.health_address,
        agent.network().cloned(),
    ));

    // Start background reconnect task for bootstrap mesh maintenance
    let reconnect_handle = tokio::spawn(maintain_bootstrap_mesh(
        agent.network().cloned(),
        config.known_peers.clone(),
    ));

    // Broadcast current manifest to gossip after joining the network.
    // Ensures peers that missed the initial gossip window still receive it.
    if config.update.enabled {
        let agent_for_broadcast = Arc::clone(&agent);
        let update_config = config.update.clone();
        tokio::spawn(async move {
            broadcast_current_manifest(
                &agent_for_broadcast,
                &update_config.repo,
                update_config.include_prereleases,
            )
            .await;
        });
    }

    // Start periodic GitHub poll (discovers releases, broadcasts to gossip)
    let update_handle = if config.update.enabled {
        let update_config = config.update.clone();
        let agent_for_update = Arc::clone(&agent);
        Some(tokio::spawn(async move {
            run_github_poll(agent_for_update, update_config).await;
        }))
    } else {
        None
    };

    // Wait for shutdown signal
    tracing::info!("Bootstrap node running. Press Ctrl+C to stop.");
    match signal::ctrl_c().await {
        Ok(()) => {
            tracing::info!("Received shutdown signal");
        }
        Err(err) => {
            tracing::error!("Failed to listen for shutdown signal: {}", err);
        }
    }

    // Graceful shutdown
    agent.shutdown().await;
    health_handle.abort();
    reconnect_handle.abort();
    if let Some(h) = update_handle {
        h.abort();
    }
    tracing::info!("Shutdown complete");

    Ok(())
}

/// Background task that periodically reconnects to missing bootstrap peers.
///
/// Bootstrap nodes should maintain a full mesh with all other bootstrap nodes.
/// This task runs every 60 seconds, checks which peers are missing, and
/// attempts to reconnect to them.
async fn maintain_bootstrap_mesh(
    network: Option<std::sync::Arc<x0x::network::NetworkNode>>,
    known_peers: Vec<SocketAddr>,
) -> Result<()> {
    let Some(network) = network else {
        return Ok(());
    };

    let expected = known_peers.len();
    // Initial delay: let join_network() finish first
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;

    loop {
        let connected = network.connection_count().await;
        if connected < expected {
            tracing::info!(
                "Mesh incomplete: {}/{} peers connected, reconnecting...",
                connected,
                expected
            );

            for peer_addr in &known_peers {
                match network.connect_addr(*peer_addr).await {
                    Ok(_) => {
                        tracing::info!("Reconnected to bootstrap peer: {}", peer_addr);
                    }
                    Err(e) => {
                        tracing::debug!("Reconnect to {} failed: {}", peer_addr, e);
                    }
                }
            }

            let new_count = network.connection_count().await;
            tracing::info!(
                "Reconnect cycle complete: {}/{} peers connected",
                new_count,
                expected
            );
        }

        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}

/// Load configuration from TOML file
async fn load_config(path: &str) -> Result<BootstrapConfig> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read config file: {}", path))?;

    toml::from_str(&content).with_context(|| format!("failed to parse config file: {}", path))
}

/// Initialize logging with configurable format
fn init_logging(level: &str, format: &str) -> Result<()> {
    let level_filter = match level.to_lowercase().as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };

    if format == "json" {
        tracing_subscriber::fmt()
            .with_max_level(level_filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(level_filter)
            .init();
    }

    Ok(())
}

/// Run HTTP health server
async fn run_health_server(
    addr: SocketAddr,
    network: Option<std::sync::Arc<x0x::network::NetworkNode>>,
) -> Result<()> {
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Body, Request, Response, Server};
    use std::convert::Infallible;

    let make_svc = make_service_fn(move |_conn| {
        let network = network.clone();
        async move {
            let network = network;
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let network = network.clone();
                async move {
                    match req.uri().path() {
                        "/health" => {
                            let peers = match &network {
                                Some(net) => net.connection_count().await,
                                None => 0,
                            };

                            let response = HealthResponse {
                                status: "healthy".to_string(),
                                peers,
                            };

                            let json = serde_json::to_string(&response)
                                .unwrap_or_else(|_| r#"{"status":"error"}"#.to_string());

                            Ok::<_, Infallible>(Response::new(Body::from(json)))
                        }
                        "/metrics" => {
                            let (peers, stats) = match &network {
                                Some(net) => {
                                    let s = net.stats().await;
                                    (s.peer_count, s)
                                }
                                None => (0, x0x::network::NetworkStats::default()),
                            };

                            let response = MetricsResponse {
                                status: "healthy".to_string(),
                                peers,
                                total_connections: stats.total_connections,
                                active_connections: stats.active_connections,
                                bytes_sent: stats.bytes_sent,
                                bytes_received: stats.bytes_received,
                            };

                            let json = serde_json::to_string(&response)
                                .unwrap_or_else(|_| r#"{"status":"error"}"#.to_string());

                            Ok::<_, Infallible>(Response::new(Body::from(json)))
                        }
                        _ => {
                            let mut not_found = Response::default();
                            *not_found.status_mut() = hyper::StatusCode::NOT_FOUND;
                            Ok::<_, Infallible>(not_found)
                        }
                    }
                }
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    tracing::info!("Health server listening on {}", addr);

    server.await.context("health server failed")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Self-update helpers
// ---------------------------------------------------------------------------

/// Run the startup update check. Returns `true` if an update was applied.
async fn run_startup_update_check(config: &BootstrapConfig) -> Result<bool> {
    let monitor = UpgradeMonitor::new(&config.update.repo, "x0x-bootstrap", x0x::VERSION)
        .map_err(|e| anyhow::anyhow!(e))?
        .with_include_prereleases(config.update.include_prereleases);

    let Some(verified) = monitor
        .check_for_updates()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
    else {
        return Ok(false);
    };

    tracing::info!(
        new_version = %verified.manifest.version,
        "Startup check: new version available, applying immediately"
    );

    let upgrader = x0x::upgrade::apply::AutoApplyUpgrader::new("x0x-bootstrap")
        .with_stop_on_upgrade(config.update.stop_on_upgrade);

    match upgrader
        .apply_upgrade_from_manifest(&verified.manifest)
        .await
    {
        Ok(x0x::upgrade::UpgradeResult::Success { version }) => {
            tracing::info!(%version, "Successfully upgraded to version {version}");
            Ok(true)
        }
        Ok(x0x::upgrade::UpgradeResult::RolledBack { reason }) => {
            tracing::warn!(%reason, "Upgrade rolled back");
            Ok(false)
        }
        Ok(x0x::upgrade::UpgradeResult::NoUpgrade) => Ok(false),
        Err(e) => {
            tracing::error!(error = %e, "Upgrade failed: {e}");
            Ok(false)
        }
    }
}

/// Broadcast the current release manifest to gossip after joining the network.
///
/// After a bootstrap node restarts (possibly after upgrading), it fetches the latest
/// manifest from GitHub and broadcasts it regardless of whether it needs to upgrade.
/// This ensures peers who missed the initial gossip window still receive the manifest.
async fn broadcast_current_manifest(agent: &Agent, repo: &str, include_prereleases: bool) {
    let monitor = match UpgradeMonitor::new(repo, "x0x-bootstrap", x0x::VERSION) {
        Ok(m) => m.with_include_prereleases(include_prereleases),
        Err(e) => {
            tracing::debug!(error = %e, "Failed to create monitor for startup broadcast");
            return;
        }
    };

    match monitor.fetch_current_manifest().await {
        Ok(Some(verified)) => {
            tracing::info!(
                version = %verified.manifest.version,
                "Broadcasting current release manifest v{} to gossip",
                verified.manifest.version
            );
            if let Err(e) = agent.publish(RELEASE_TOPIC, verified.gossip_payload).await {
                tracing::debug!(error = %e, "Failed to broadcast current manifest: {e}");
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::debug!(error = %e, "Failed to fetch current manifest for broadcast: {e}");
        }
    }
}

/// Periodic GitHub poll: discovers releases and broadcasts to gossip.
///
/// Bootstrap's update flow is symmetric with x0xd — discover, verify manifest,
/// broadcast to gossip, apply. Different config defaults (1h poll, 2h rollout,
/// stop_on_upgrade=true).
///
/// Tracks versions that failed to apply and skips them for 30 minutes before
/// retrying. A newer release superseding the failed version will be picked up
/// immediately.
async fn run_github_poll(agent: Arc<Agent>, config: UpdateConfig) {
    let check_interval = Duration::from_secs(config.check_interval_seconds);
    let mut ticker = tokio::time::interval(check_interval);
    // Skip first tick (startup check already ran)
    ticker.tick().await;

    let mut failed_version: Option<(String, std::time::Instant)> = None;
    const RETRY_AFTER: Duration = Duration::from_secs(30 * 60);

    loop {
        ticker.tick().await;
        tracing::debug!("GitHub poll check");

        // Clear expired failure skip
        if let Some((_, failed_at)) = &failed_version {
            if failed_at.elapsed() >= RETRY_AFTER {
                tracing::info!("Retry timeout elapsed, clearing failed version skip");
                failed_version = None;
            }
        }

        let monitor = match UpgradeMonitor::new(&config.repo, "x0x-bootstrap", x0x::VERSION) {
            Ok(m) => m.with_include_prereleases(config.include_prereleases),
            Err(e) => {
                tracing::warn!(error = %e, "Failed to create upgrade monitor: {e}");
                continue;
            }
        };

        match monitor.check_for_updates().await {
            Ok(Some(verified)) => {
                // Skip versions that recently failed to apply
                if let Some((ref ver, _)) = failed_version {
                    if ver == &verified.manifest.version {
                        tracing::debug!(
                            version = %verified.manifest.version,
                            "Skipping recently failed version {}",
                            verified.manifest.version
                        );
                        continue;
                    }
                }

                tracing::info!(
                    new_version = %verified.manifest.version,
                    "GitHub poll: new version found"
                );

                // Broadcast to gossip with timeout — don't let dead peers block upgrade
                let publish_payload = verified.gossip_payload.clone();
                let publish_agent = agent.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        Duration::from_secs(10),
                        publish_agent.publish(RELEASE_TOPIC, publish_payload),
                    )
                    .await
                    {
                        Ok(Ok(())) => {
                            tracing::debug!("Broadcast discovered release to gossip");
                        }
                        Ok(Err(e)) => {
                            tracing::debug!(error = %e, "Failed to broadcast discovered release: {e}");
                        }
                        Err(_) => {
                            tracing::debug!(
                                "Gossip broadcast timed out (peers may be unreachable)"
                            );
                        }
                    }
                });

                let upgrader = x0x::upgrade::apply::AutoApplyUpgrader::new("x0x-bootstrap")
                    .with_stop_on_upgrade(config.stop_on_upgrade);
                match upgrader
                    .apply_upgrade_from_manifest(&verified.manifest)
                    .await
                {
                    Ok(x0x::upgrade::UpgradeResult::Success { version }) => {
                        tracing::info!(%version, "GitHub poll upgrade successful");
                    }
                    Ok(x0x::upgrade::UpgradeResult::RolledBack { reason }) => {
                        tracing::warn!(%reason, "GitHub poll upgrade rolled back");
                        failed_version =
                            Some((verified.manifest.version.clone(), std::time::Instant::now()));
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "GitHub poll upgrade failed: {e}");
                        failed_version =
                            Some((verified.manifest.version.clone(), std::time::Instant::now()));
                    }
                    _ => {}
                }
            }
            Ok(None) => {
                tracing::debug!("GitHub poll: up to date");
            }
            Err(e) => {
                tracing::warn!(error = %e, "GitHub poll check failed: {e}");
            }
        }
    }
}
