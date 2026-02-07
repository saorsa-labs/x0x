//! x0x bootstrap node
//!
//! A coordinator/reflector node for the x0x network that provides:
//! - Network bootstrap endpoints for new agents
//! - Rendezvous coordination
//! - Relay services for NAT traversal
//! - Health monitoring endpoint

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::signal;
use x0x::network::NetworkConfig;
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

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:12000".parse().expect("valid address"),
            health_address: "127.0.0.1:12600".parse().expect("valid address"),
            machine_key_path: default_machine_key_path(),
            data_dir: default_data_dir(),
            coordinator: true,
            reflector: true,
            relay: true,
            known_peers: Vec::new(),
            log_level: "info".to_string(),
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

    // Load configuration
    let config = load_config(&config_path).await?;

    // Initialize logging
    init_logging(&config.log_level)?;

    if check_only {
        println!("Configuration is valid");
        println!("{:#?}", config);
        return Ok(());
    }

    // Log startup
    tracing::info!("Starting x0x bootstrap node v{}", x0x::VERSION);
    tracing::info!("Bind address: {}", config.bind_address);
    tracing::info!("Health endpoint: {}", config.health_address);
    tracing::info!("Coordinator: {}", config.coordinator);
    tracing::info!("Reflector: {}", config.reflector);
    tracing::info!("Relay: {}", config.relay);
    tracing::info!("Known peers: {:?}", config.known_peers);

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

    let agent = Agent::builder()
        .with_machine_key(&config.machine_key_path)
        .with_network_config(network_config)
        .build()
        .await
        .context("failed to create agent")?;

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
    health_handle.abort();
    tracing::info!("Shutdown complete");

    Ok(())
}

/// Load configuration from TOML file
async fn load_config(path: &str) -> Result<BootstrapConfig> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read config file: {}", path))?;

    toml::from_str(&content).with_context(|| format!("failed to parse config file: {}", path))
}

/// Initialize logging with structured output
fn init_logging(level: &str) -> Result<()> {
    let level_filter = match level.to_lowercase().as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };

    tracing_subscriber::fmt()
        .with_max_level(level_filter)
        .json()
        .init();

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
