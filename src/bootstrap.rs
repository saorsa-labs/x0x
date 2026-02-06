//! Bootstrap node discovery and connection logic.
//!
//! This module handles initial connection to bootstrap nodes with
//! retry logic and peer cache integration.

use crate::error::{NetworkError, NetworkResult};
use crate::network::{NetworkNode, PeerCache};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;

/// Bootstrap configuration for connecting to initial peers.
///
/// Controls retry behavior and connection strategy for bootstrap nodes.
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// Number of retry attempts for each bootstrap node.
    pub max_retries: u32,
    /// Backoff multiplier for exponential backoff (default 2.0).
    pub backoff_multiplier: f64,
    /// Initial backoff duration.
    pub initial_backoff: Duration,
    /// Maximum backoff duration.
    pub max_backoff: Duration,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff_multiplier: 2.0,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
        }
    }
}

/// Bootstrap node connector with retry logic.
///
/// Handles discovery and connection to bootstrap nodes with exponential backoff.
pub struct BootstrapConnector {
    config: BootstrapConfig,
}

impl BootstrapConnector {
    /// Create a new bootstrap connector with default configuration.
    pub fn new() -> Self {
        Self {
            config: BootstrapConfig::default(),
        }
    }

    /// Create a bootstrap connector with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Bootstrap configuration with retry parameters.
    pub fn with_config(config: BootstrapConfig) -> Self {
        Self { config }
    }

    /// Connect to bootstrap nodes from peer cache.
    ///
    /// Attempts to connect to cached bootstrap peers using epsilon-greedy selection.
    ///
    /// # Arguments
    ///
    /// * `node` - The network node to use for connections.
    /// * `cache` - The peer cache with bootstrap node information.
    /// * `count` - Number of peers to attempt connection to.
    ///
    /// # Returns
    ///
    /// Number of successful connections.
    ///
    /// # Errors
    ///
    /// Returns error if node is not initialized, but partial success is acceptable.
    pub async fn connect_cached_peers(
        &self,
        node: &NetworkNode,
        cache: &PeerCache,
        count: usize,
    ) -> NetworkResult<usize> {
        let peers = cache.select_peers(count);
        let mut success_count = 0;

        for addr in peers {
            if self.connect_with_retry(node, addr).await.is_ok() {
                success_count += 1;
            }
        }

        Ok(success_count)
    }

    /// Connect to a bootstrap node with exponential backoff retry.
    ///
    /// # Arguments
    ///
    /// * `node` - The network node to use for connection.
    /// * `addr` - Address of the bootstrap node.
    ///
    /// # Returns
    ///
    /// Ok with the peer ID on success.
    ///
    /// # Errors
    ///
    /// Returns error if all retry attempts fail.
    pub async fn connect_with_retry(
        &self,
        node: &NetworkNode,
        addr: SocketAddr,
    ) -> NetworkResult<()> {
        let mut backoff = self.config.initial_backoff;
        let mut attempt = 0;

        loop {
            match node.connect_addr(addr).await {
                Ok(_peer_id) => {
                    return Ok(());
                }
                Err(e) => {
                    attempt += 1;
                    if attempt >= self.config.max_retries {
                        return Err(NetworkError::ConnectionFailed(format!(
                            "Bootstrap connection failed after {} attempts: {}",
                            attempt, e
                        )));
                    }

                    // Apply exponential backoff
                    sleep(backoff).await;
                    backoff = std::cmp::min(
                        Duration::from_secs_f64(backoff.as_secs_f64() * self.config.backoff_multiplier),
                        self.config.max_backoff,
                    );
                }
            }
        }
    }

    /// Connect to multiple bootstrap addresses in parallel.
    ///
    /// # Arguments
    ///
    /// * `node` - The network node to use.
    /// * `addrs` - Bootstrap addresses to connect to.
    ///
    /// # Returns
    ///
    /// Number of successful connections.
    pub async fn connect_multiple(
        &self,
        node: &NetworkNode,
        addrs: &[SocketAddr],
    ) -> usize {
        let mut handles = Vec::new();

        for &addr in addrs {
            let node_clone = node.clone();
            let config = self.config.clone();
            let handle = tokio::spawn(async move {
                let connector = BootstrapConnector::with_config(config);
                connector.connect_with_retry(&node_clone, addr).await.is_ok()
            });
            handles.push(handle);
        }

        let mut success_count = 0;
        for handle in handles {
            if let Ok(success) = handle.await {
                if success {
                    success_count += 1;
                }
            }
        }

        success_count
    }
}

impl Default for BootstrapConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_config_default() {
        let config = BootstrapConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.backoff_multiplier, 2.0);
        assert_eq!(config.initial_backoff, Duration::from_millis(100));
        assert_eq!(config.max_backoff, Duration::from_secs(5));
    }

    #[test]
    fn test_bootstrap_config_custom() {
        let config = BootstrapConfig {
            max_retries: 5,
            backoff_multiplier: 1.5,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_secs(10),
        };
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.backoff_multiplier, 1.5);
    }

    #[test]
    fn test_bootstrap_connector_new() {
        let connector = BootstrapConnector::new();
        assert_eq!(connector.config.max_retries, 3);
    }

    #[test]
    fn test_bootstrap_connector_with_config() {
        let config = BootstrapConfig {
            max_retries: 2,
            backoff_multiplier: 2.0,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
        };
        let connector = BootstrapConnector::with_config(config.clone());
        assert_eq!(connector.config.max_retries, 2);
    }

    #[test]
    fn test_bootstrap_connector_default() {
        let connector = BootstrapConnector::default();
        assert_eq!(connector.config.max_retries, 3);
    }

    #[test]
    fn test_exponential_backoff_calculation() {
        let config = BootstrapConfig {
            max_retries: 3,
            backoff_multiplier: 2.0,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
        };

        let mut backoff = config.initial_backoff;
        assert_eq!(backoff, Duration::from_millis(100));

        // First retry: 100ms * 2 = 200ms
        backoff = Duration::from_secs_f64(backoff.as_secs_f64() * config.backoff_multiplier);
        assert_eq!(backoff, Duration::from_millis(200));

        // Second retry: 200ms * 2 = 400ms
        backoff = Duration::from_secs_f64(backoff.as_secs_f64() * config.backoff_multiplier);
        assert_eq!(backoff, Duration::from_millis(400));

        // Third retry: 400ms * 2 = 800ms
        backoff = Duration::from_secs_f64(backoff.as_secs_f64() * config.backoff_multiplier);
        assert_eq!(backoff, Duration::from_millis(800));
    }

    #[test]
    fn test_max_backoff_clamping() {
        let config = BootstrapConfig {
            max_retries: 5,
            backoff_multiplier: 2.0,
            initial_backoff: Duration::from_millis(1000),
            max_backoff: Duration::from_secs(5),
        };

        let mut backoff = config.initial_backoff;

        // Keep applying backoff multiplier
        for _ in 0..5 {
            backoff = std::cmp::min(
                Duration::from_secs_f64(backoff.as_secs_f64() * config.backoff_multiplier),
                config.max_backoff,
            );
        }

        // Should never exceed max_backoff
        assert!(backoff <= config.max_backoff);
    }
}
