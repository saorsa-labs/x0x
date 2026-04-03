//! mDNS local network discovery for x0x agents.
//!
//! Registers each agent as a `_x0x._udp.local.` DNS-SD service so that
//! other x0x instances on the same LAN can discover and connect without
//! requiring bootstrap nodes or explicit addresses.
//!
//! TXT records carry: `agent_id`, `machine_id`, `words` (four-word
//! speakable identity), and `version`.

use crate::identity::{AgentId, MachineId};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// DNS-SD service type for x0x agents.
pub const SERVICE_TYPE: &str = "_x0x._udp.local.";

/// A peer discovered via mDNS on the local network.
#[derive(Debug, Clone)]
pub struct MdnsDiscoveredPeer {
    /// The agent's identifier.
    pub agent_id: AgentId,
    /// The machine identifier.
    pub machine_id: MachineId,
    /// Four-word speakable identity.
    pub words: String,
    /// Routable addresses for the QUIC endpoint (loopback filtered out).
    pub addrs: Vec<SocketAddr>,
    /// The crate version reported by the peer.
    pub version: String,
}

/// mDNS service discovery for x0x agents.
///
/// Wraps `mdns_sd::ServiceDaemon` to register this agent on the LAN
/// and browse for other agents.  All methods are safe to call from
/// async code — the underlying daemon runs on its own thread.
///
/// Implements `Drop` to ensure the daemon thread and browse task are
/// cleaned up even if `shutdown()` is not called explicitly.
pub struct MdnsDiscovery {
    daemon: mdns_sd::ServiceDaemon,
    /// Our registered fullname for self-filtering and unregister.
    instance_fullname: String,
    /// Peers discovered via mDNS browse, keyed by instance fullname.
    discovered: Arc<RwLock<HashMap<String, MdnsDiscoveredPeer>>>,
    /// Handle for the background browse task.
    browse_handle: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Whether `start_browse` has been called (idempotency guard).
    browse_started: AtomicBool,
    /// Whether `shutdown` has been called (prevents double-shutdown in Drop).
    shut_down: AtomicBool,
}

impl MdnsDiscovery {
    /// Create a new mDNS discovery instance and register this agent.
    ///
    /// - `agent_id`: This agent's identifier (hex in TXT record).
    /// - `machine_id`: This machine's identifier (hex in TXT record).
    /// - `words`: Four-word speakable identity string.
    /// - `port`: The QUIC port this agent is listening on.
    pub fn new(
        agent_id: &AgentId,
        machine_id: &MachineId,
        words: &str,
        port: u16,
    ) -> Result<Self, String> {
        let daemon = mdns_sd::ServiceDaemon::new().map_err(|e| format!("mDNS daemon: {e}"))?;

        // Instance name must be unique per (agent, machine) pair because
        // agent keys are portable across machines.  Use 8 bytes of each ID
        // (16 hex chars each) for 128 bits total, well under the 63-byte
        // DNS label limit: "x0x-" (4) + 16 + "-" (1) + 16 = 37 bytes.
        let instance_name = format!(
            "x0x-{}-{}",
            &hex::encode(agent_id.0)[..16],
            &hex::encode(machine_id.0)[..16]
        );
        let instance_fullname = format!("{instance_name}.{SERVICE_TYPE}");

        let agent_hex = hex::encode(agent_id.0);
        let machine_hex = hex::encode(machine_id.0);
        let version = env!("CARGO_PKG_VERSION");

        let properties: Vec<(&str, &str)> = vec![
            ("agent_id", agent_hex.as_str()),
            ("machine_id", machine_hex.as_str()),
            ("words", words),
            ("version", version),
        ];

        // Hostname: use the instance name with .local. suffix.
        let hostname = format!("{instance_name}.local.");

        let service_info = mdns_sd::ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &hostname,
            "", // empty IP = let mdns-sd auto-detect all interfaces
            port,
            properties.as_slice(),
        )
        .map_err(|e| format!("mDNS ServiceInfo: {e}"))?
        .enable_addr_auto();

        daemon
            .register(service_info)
            .map_err(|e| format!("mDNS register: {e}"))?;

        tracing::info!(
            "mDNS: registered {instance_name} on port {port} ({})",
            words
        );

        Ok(Self {
            daemon,
            instance_fullname,
            discovered: Arc::new(RwLock::new(HashMap::new())),
            browse_handle: Arc::new(tokio::sync::Mutex::new(None)),
            browse_started: AtomicBool::new(false),
            shut_down: AtomicBool::new(false),
        })
    }

    /// Start browsing for other x0x agents on the LAN.
    ///
    /// Spawns a background task that processes mDNS browse events and
    /// populates the discovered peers map.  Returns immediately.
    ///
    /// Calling this more than once is a no-op — the browse task is
    /// idempotent.
    pub async fn start_browse(&self) -> Result<(), String> {
        // Atomic idempotency: CAS ensures exactly one caller wins.
        if self
            .browse_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }

        let receiver = match self.daemon.browse(SERVICE_TYPE) {
            Ok(r) => r,
            Err(e) => {
                // Reset so a future call can retry after transient failure.
                self.browse_started.store(false, Ordering::SeqCst);
                return Err(format!("mDNS browse: {e}"));
            }
        };

        let discovered = Arc::clone(&self.discovered);
        let our_fullname = self.instance_fullname.clone();

        let handle = tokio::task::spawn(async move {
            // The mdns-sd receiver is sync, so we use spawn_blocking
            // inside a loop to avoid blocking the tokio runtime.
            loop {
                let rx_clone = receiver.clone();
                let event = tokio::task::spawn_blocking(move || {
                    // Block for up to 2 seconds waiting for an event.
                    rx_clone.recv_timeout(std::time::Duration::from_secs(2))
                })
                .await;

                match event {
                    Ok(Ok(mdns_sd::ServiceEvent::ServiceResolved(info))) => {
                        // Skip our own registration (exact fullname match).
                        let full_name = info.get_fullname().to_string();
                        if full_name == our_fullname {
                            continue;
                        }

                        let props = info.get_properties();
                        let agent_hex = props
                            .get("agent_id")
                            .map(|p| p.val_str().to_string())
                            .unwrap_or_default();
                        let machine_hex = props
                            .get("machine_id")
                            .map(|p| p.val_str().to_string())
                            .unwrap_or_default();
                        let words = props
                            .get("words")
                            .map(|p| p.val_str().to_string())
                            .unwrap_or_default();
                        let version = props
                            .get("version")
                            .map(|p| p.val_str().to_string())
                            .unwrap_or_default();

                        // Parse agent_id and machine_id from hex.
                        let agent_id = match hex::decode(&agent_hex) {
                            Ok(bytes) if bytes.len() == 32 => {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&bytes);
                                AgentId(arr)
                            }
                            _ => {
                                tracing::warn!("mDNS: invalid agent_id hex from {full_name}");
                                continue;
                            }
                        };
                        let machine_id = match hex::decode(&machine_hex) {
                            Ok(bytes) if bytes.len() == 32 => {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&bytes);
                                MachineId(arr)
                            }
                            _ => {
                                tracing::warn!("mDNS: invalid machine_id hex from {full_name}");
                                continue;
                            }
                        };

                        // Collect routable addresses, filtering out:
                        // - Loopback (127.0.0.1 / ::1)
                        // - Link-local IPv6 (fe80::) — needs scope_id not in SocketAddr
                        // - APIPA / link-local IPv4 (169.254.x.x)
                        // Deduplicate via collect into a set then back to Vec.
                        let port = info.get_port();
                        let addr_set: std::collections::HashSet<SocketAddr> = info
                            .get_addresses()
                            .iter()
                            .map(|ip| SocketAddr::new(ip.to_ip_addr(), port))
                            .filter(|a| is_routable(a.ip()))
                            .collect();
                        let addrs: Vec<SocketAddr> = addr_set.into_iter().collect();

                        if addrs.is_empty() {
                            tracing::debug!("mDNS: skipping {full_name} — no routable addresses");
                            continue;
                        }

                        // Only log the first time we discover this peer.
                        let is_new = !discovered.read().await.contains_key(&full_name);
                        if is_new {
                            tracing::info!(
                                "mDNS: discovered agent {} at {:?} ({})",
                                &agent_hex[..12],
                                addrs,
                                words
                            );
                        }
                        let peer = MdnsDiscoveredPeer {
                            agent_id,
                            machine_id,
                            words,
                            addrs,
                            version,
                        };
                        discovered.write().await.insert(full_name, peer);
                    }
                    Ok(Ok(mdns_sd::ServiceEvent::ServiceRemoved(_, full_name))) => {
                        tracing::info!("mDNS: agent removed: {full_name}");
                        discovered.write().await.remove(&full_name);
                    }
                    Ok(Ok(_)) => {
                        // ServiceFound, SearchStarted, SearchStopped — ignore.
                    }
                    Ok(Err(_)) => {
                        // Timeout — normal, just loop.
                    }
                    Err(e) => {
                        // spawn_blocking join error — task was cancelled.
                        tracing::debug!("mDNS browse task ended: {e}");
                        break;
                    }
                }
            }
        });

        // Store the handle synchronously so shutdown() can always find it.
        *self.browse_handle.lock().await = Some(handle);

        tracing::info!("mDNS: browsing for LAN agents on {SERVICE_TYPE}");
        Ok(())
    }

    /// Return a snapshot of all currently discovered LAN peers.
    pub async fn discovered_peers(&self) -> Vec<MdnsDiscoveredPeer> {
        self.discovered.read().await.values().cloned().collect()
    }

    /// Shut down mDNS — unregister the service and stop browsing.
    pub async fn shutdown(&self) {
        // Prevent double shutdown (Drop may also call cleanup).
        if self.shut_down.swap(true, Ordering::SeqCst) {
            return;
        }

        // Abort the browse task.
        if let Some(handle) = self.browse_handle.lock().await.take() {
            handle.abort();
        }

        // Unregister our service.
        if let Err(e) = self.daemon.unregister(&self.instance_fullname) {
            tracing::warn!("mDNS: unregister failed: {e}");
        }

        // Shut down the daemon thread.
        if let Err(e) = self.daemon.shutdown() {
            tracing::warn!("mDNS: shutdown failed: {e}");
        }

        tracing::info!("mDNS: shut down");
    }
}

/// Clean up daemon thread and browse task if dropped without `shutdown()`.
impl Drop for MdnsDiscovery {
    fn drop(&mut self) {
        if self.shut_down.load(Ordering::SeqCst) {
            return; // Already shut down via shutdown().
        }

        // Abort the browse task (JoinHandle::abort is sync-safe).
        if let Ok(mut guard) = self.browse_handle.try_lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }

        // Unregister service and stop daemon thread.
        let _ = self.daemon.unregister(&self.instance_fullname);
        let _ = self.daemon.shutdown();
    }
}

/// Returns true if the IP is routable on a LAN (not loopback, not
/// link-local IPv6, not APIPA/link-local IPv4).
fn is_routable(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_loopback() && !v4.is_link_local() // filters 169.254.x.x
        }
        std::net::IpAddr::V6(v6) => {
            // fe80::/10 = link-local, needs scope_id which SocketAddr doesn't carry.
            let segs = v6.segments();
            let is_link_local = (segs[0] & 0xffc0) == 0xfe80;
            !v6.is_loopback() && !is_link_local
        }
    }
}
