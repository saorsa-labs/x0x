#![allow(dead_code)]
//! Three-agent daemon orchestration for integration tests.
//!
//! Provides `AgentCluster` which manages 3 x0xd daemon processes
//! (alice, bob, charlie) with mutual discovery for multi-agent testing.

use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::sync::OnceCell;

/// A single x0xd daemon instance.
pub struct AgentInstance {
    process: Child,
    binary: PathBuf,
    config_path: PathBuf,
    /// Instance name (e.g., "alice-12345").
    pub name: String,
    /// API address (e.g., "127.0.0.1:19101").
    pub api_addr: String,
    /// Bearer token for authentication.
    pub api_token: String,
    /// Data directory (cleaned up on drop if temp).
    data_dir: PathBuf,
}

#[allow(dead_code)]
impl AgentInstance {
    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    pub fn directory_subscriptions_path(&self) -> PathBuf {
        self.data_dir.join("directory-subscriptions.json")
    }

    pub async fn restart(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        self.process = Command::new(&self.binary)
            .arg("--config")
            .arg(&self.config_path)
            .arg("--name")
            .arg(&self.name)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("Failed to restart x0xd {}: {e}", self.name));
        self.refresh_runtime_state().await;
    }

    async fn refresh_runtime_state(&mut self) {
        let api_addr = self.api_addr.clone();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let client = reqwest::Client::new();
        loop {
            if let Ok(resp) = client.get(format!("http://{api_addr}/health")).send().await {
                if resp.status().is_success() {
                    break;
                }
            }
            if tokio::time::Instant::now() > deadline {
                panic!("x0xd {} did not become healthy within 30s", self.name);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let token_file = self.data_dir.join("api-token");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(token) = std::fs::read_to_string(&token_file) {
                let token = token.trim().to_string();
                if !token.is_empty() {
                    self.api_token = token;
                    return;
                }
            }
            if tokio::time::Instant::now() > deadline {
                panic!("Cannot find api-token for {}", self.name);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Full URL for a given API path.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.api_addr, path)
    }

    /// WebSocket URL with token in query parameter.
    pub fn ws_url(&self, path: &str) -> String {
        format!("ws://{}{}?token={}", self.api_addr, path, self.api_token)
    }

    /// Authenticated GET request.
    pub async fn get(&self, path: &str) -> reqwest::Response {
        reqwest::Client::new()
            .get(self.url(path))
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .expect("GET request failed")
    }

    /// Authenticated POST request with JSON body.
    pub async fn post(&self, path: &str, body: serde_json::Value) -> reqwest::Response {
        reqwest::Client::new()
            .post(self.url(path))
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(&body)
            .send()
            .await
            .expect("POST request failed")
    }

    /// Authenticated PUT request with JSON body.
    pub async fn put(&self, path: &str, body: serde_json::Value) -> reqwest::Response {
        reqwest::Client::new()
            .put(self.url(path))
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(&body)
            .send()
            .await
            .expect("PUT request failed")
    }

    /// Authenticated PATCH request with JSON body.
    pub async fn patch(&self, path: &str, body: serde_json::Value) -> reqwest::Response {
        reqwest::Client::new()
            .patch(self.url(path))
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(&body)
            .send()
            .await
            .expect("PATCH request failed")
    }

    /// Authenticated DELETE request.
    pub async fn delete(&self, path: &str) -> reqwest::Response {
        reqwest::Client::new()
            .delete(self.url(path))
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .expect("DELETE request failed")
    }

    /// Unauthenticated GET request.
    pub async fn raw_get(&self, path: &str) -> reqwest::Response {
        reqwest::Client::new()
            .get(self.url(path))
            .send()
            .await
            .expect("raw GET request failed")
    }

    /// Get this agent's ID by calling GET /agent.
    pub async fn agent_id(&self) -> String {
        let resp: serde_json::Value = self.get("/agent").await.json().await.expect("parse agent");
        resp["agent_id"]
            .as_str()
            .expect("agent_id field")
            .to_string()
    }
}

/// Three x0xd daemon instances for multi-agent testing.
pub struct AgentCluster {
    pub alice: AgentInstance,
    pub bob: AgentInstance,
    #[allow(dead_code)]
    pub charlie: AgentInstance,
}

/// Two-daemon local pair for deterministic cross-peer tests.
pub struct AgentPair {
    pub alice: AgentInstance,
    pub bob: AgentInstance,
}

impl Drop for AgentInstance {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl Drop for AgentCluster {
    fn drop(&mut self) {
        // AgentInstance::drop handles killing each process.
        // Explicit drop order: charlie, bob, alice (reverse of start).
        // (Rust drops fields in declaration order, which is alice, bob, charlie —
        //  but the order doesn't matter for cleanup, just that it happens.)
    }
}

impl Drop for AgentPair {
    fn drop(&mut self) {
        // AgentInstance::drop handles child cleanup.
    }
}

static CLUSTER: OnceCell<AgentCluster> = OnceCell::const_new();

/// Returns a shared `AgentCluster` singleton.
///
/// The cluster is created once per test binary (via `OnceCell`) and reused
/// across all tests in the same binary. This matches nextest's model where
/// each test file is a separate process.
///
/// # Panics
///
/// Panics if x0xd binary is not found or agents fail to start.
pub async fn cluster() -> &'static AgentCluster {
    CLUSTER.get_or_init(create_cluster).await
}

/// Start a fresh two-daemon pair with Bob bootstrapping to Alice.
pub async fn pair() -> AgentPair {
    pair_with_extra_config("").await
}

pub async fn trio_with_extra_config(extra_config: &str) -> AgentCluster {
    create_cluster_with_extra_config(extra_config).await
}

/// Start a fresh pair with the same extra TOML appended to each daemon's
/// generated config. Useful for test-only timing overrides.
pub async fn pair_with_extra_config(extra_config: &str) -> AgentPair {
    let binary = find_x0xd_binary();
    let suffix = rand::random::<u16>();
    let alice_api = allocate_unused_tcp_port();
    let alice_bind = allocate_unused_udp_port();
    let bob_api = allocate_unused_tcp_port();
    let bob_bind = allocate_unused_udp_port();

    let alice = start_instance(
        &binary,
        &format!("pair-alice-{suffix}"),
        alice_api,
        alice_bind,
        "",
        extra_config,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    let bob = start_instance(
        &binary,
        &format!("pair-bob-{suffix}"),
        bob_api,
        bob_bind,
        &format!("bootstrap_peers = [\"127.0.0.1:{alice_bind}\"]"),
        extra_config,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(5)).await;

    AgentPair { alice, bob }
}

/// Delay between starting each node to allow connections and the gossip
/// mesh to form. Discovered empirically — without this rolling start,
/// nodes that come up simultaneously fail to establish stable connections.
const ROLLING_START_DELAY: Duration = Duration::from_secs(15);

/// Extra settling time after all nodes are up, before we start checking
/// for peers. Gives the mesh time to fully stabilise.
const MESH_SETTLE_TIME: Duration = Duration::from_secs(5);

async fn create_cluster() -> AgentCluster {
    create_cluster_with_extra_config("").await
}

async fn create_cluster_with_extra_config(extra_config: &str) -> AgentCluster {
    let binary = find_x0xd_binary();
    let suffix = rand::random::<u16>();
    let alice_api = allocate_unused_tcp_port();
    let alice_bind = allocate_unused_udp_port();
    let bob_api = allocate_unused_tcp_port();
    let bob_bind = allocate_unused_udp_port();
    let charlie_api = allocate_unused_tcp_port();
    let charlie_bind = allocate_unused_udp_port();

    // Rolling start: each node needs time for its QUIC listener to bind and
    // mDNS/bootstrap to propagate before the next node comes up. Starting
    // all three simultaneously causes connection races and mesh instability.

    eprintln!("[cluster] starting alice...");
    let alice = start_instance(
        &binary,
        &format!("test-alice-{suffix}"),
        alice_api,
        alice_bind,
        "",
        extra_config,
    )
    .await;

    eprintln!(
        "[cluster] waiting {}s for alice to stabilise before starting bob...",
        ROLLING_START_DELAY.as_secs()
    );
    tokio::time::sleep(ROLLING_START_DELAY).await;

    eprintln!("[cluster] starting bob (bootstraps to alice)...");
    let bob = start_instance(
        &binary,
        &format!("test-bob-{suffix}"),
        bob_api,
        bob_bind,
        &format!("bootstrap_peers = [\"127.0.0.1:{alice_bind}\"]"),
        extra_config,
    )
    .await;

    eprintln!(
        "[cluster] waiting {}s for bob to join mesh before starting charlie...",
        ROLLING_START_DELAY.as_secs()
    );
    tokio::time::sleep(ROLLING_START_DELAY).await;

    eprintln!("[cluster] starting charlie (bootstraps to alice)...");
    let charlie = start_instance(
        &binary,
        &format!("test-charlie-{suffix}"),
        charlie_api,
        charlie_bind,
        &format!("bootstrap_peers = [\"127.0.0.1:{alice_bind}\"]"),
        extra_config,
    )
    .await;

    // Give the full mesh a moment to settle after all three are up
    eprintln!(
        "[cluster] all nodes up — waiting {}s for mesh to settle...",
        MESH_SETTLE_TIME.as_secs()
    );
    tokio::time::sleep(MESH_SETTLE_TIME).await;

    // Enforce mesh connectivity — alice must see at least one peer.
    // A disconnected cluster is useless for integration tests, so we
    // panic rather than silently producing flaky results.
    assert_mesh_connected(&alice, &bob, &charlie).await;

    AgentCluster {
        alice,
        bob,
        charlie,
    }
}

/// Verify that the three-node mesh is connected. Panics if any node
/// cannot see at least one peer within 30 seconds.
async fn assert_mesh_connected(
    alice: &AgentInstance,
    bob: &AgentInstance,
    charlie: &AgentInstance,
) {
    for node in [alice, bob, charlie] {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let resp: serde_json::Value = node.get("/peers").await.json().await.unwrap_or_default();
            let peers = resp
                .as_array()
                .or_else(|| resp["peers"].as_array())
                .map_or(0, |a| a.len());
            if peers > 0 {
                eprintln!("[cluster] {} sees {peers} peer(s)", node.name);
                break;
            }
            if tokio::time::Instant::now() > deadline {
                panic!(
                    "[cluster] FATAL: {} has zero peers after 30s — mesh is disconnected. \
                     Integration tests require a connected cluster. \
                     Check that x0xd bootstrap and mDNS are working.",
                    node.name
                );
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    eprintln!("[cluster] mesh verified — all 3 nodes connected");
}

fn find_x0xd_binary() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_x0xd") {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
    }
    // From tests/harness/, the project root is ../../
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let debug = PathBuf::from(manifest_dir).join("target/debug/x0xd");
    if debug.exists() {
        return debug;
    }
    let release = PathBuf::from(manifest_dir).join("target/release/x0xd");
    if release.exists() {
        return release;
    }
    let legacy = PathBuf::from(manifest_dir).join("../../target/release/x0xd");
    if legacy.exists() {
        return legacy;
    }
    panic!(
        "x0xd binary not found. Build first: cargo build --bin x0xd\n\
         Searched: {}, {}, {}",
        debug.display(),
        release.display(),
        legacy.display()
    );
}

fn allocate_unused_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral TCP port")
        .local_addr()
        .expect("tcp local addr")
        .port()
}

fn allocate_unused_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind ephemeral UDP port")
        .local_addr()
        .expect("udp local addr")
        .port()
}

async fn start_instance(
    binary: &PathBuf,
    name: &str,
    api_port: u16,
    bind_port: u16,
    bootstrap: &str,
    extra_config: &str,
) -> AgentInstance {
    let config_dir = std::env::temp_dir().join(format!("x0x-test-{name}"));
    let _ = std::fs::remove_dir_all(&config_dir);
    let _ = std::fs::create_dir_all(&config_dir);

    // Kill stale daemons from prior failed runs that may still own these fixed ports.
    for port in [api_port, bind_port] {
        let _ = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "lsof -ti tcp:{port} 2>/dev/null | xargs kill -9 2>/dev/null || true"
            ))
            .status();
    }

    let config_path = config_dir.join("config.toml");
    let config_content = format!(
        "api_address = \"127.0.0.1:{api_port}\"\n\
         bind_address = \"0.0.0.0:{bind_port}\"\n\
         data_dir = \"{}\"\n\
         log_level = \"warn\"\n\
         {bootstrap}\n\
         {extra_config}\n",
        config_dir.display()
    );
    std::fs::write(&config_path, &config_content).expect("write config");

    let stdout_path = config_dir.join("daemon.stdout.log");
    let stderr_path = config_dir.join("daemon.stderr.log");
    let stdout = std::fs::File::create(&stdout_path)
        .unwrap_or_else(|e| panic!("Failed to create stdout log for {name}: {e}"));
    let stderr = std::fs::File::create(&stderr_path)
        .unwrap_or_else(|e| panic!("Failed to create stderr log for {name}: {e}"));

    let process = Command::new(binary)
        .arg("--config")
        .arg(&config_path)
        .arg("--name")
        .arg(name)
        .arg("--no-hard-coded-bootstrap")
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .unwrap_or_else(|e| panic!("Failed to start x0xd {name}: {e}"));

    // Wrap the Child in an AgentInstance immediately so that Drop kills
    // the process if anything below panics (health timeout, token read, etc.).
    // We'll fill in api_token once we have it.
    let api_addr = format!("127.0.0.1:{api_port}");
    let mut instance = AgentInstance {
        process,
        binary: binary.clone(),
        config_path: config_path.clone(),
        name: name.to_string(),
        api_addr: api_addr.clone(),
        api_token: String::new(), // placeholder — filled below
        data_dir: config_dir.clone(),
    };

    // Wait for health / token — if this panics, `instance` is dropped,
    // killing the process.
    instance.refresh_runtime_state().await;
    instance
}
