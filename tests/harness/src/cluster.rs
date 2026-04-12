#![allow(dead_code)]
//! Three-agent daemon orchestration for integration tests.
//!
//! Provides `AgentCluster` which manages 3 x0xd daemon processes
//! (alice, bob, charlie) with mutual discovery for multi-agent testing.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::sync::OnceCell;

/// A single x0xd daemon instance.
pub struct AgentInstance {
    process: Child,
    /// Instance name (e.g., "alice-12345").
    pub name: String,
    /// API address (e.g., "127.0.0.1:19101").
    pub api_addr: String,
    /// Bearer token for authentication.
    pub api_token: String,
    /// Data directory (cleaned up on drop if temp).
    _data_dir: PathBuf,
}

#[allow(dead_code)]
impl AgentInstance {
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
    let binary = find_x0xd_binary();
    let suffix = rand::random::<u16>();
    let base: u16 = 19300 + (suffix % 200) * 2;

    let alice = start_instance(
        &binary,
        &format!("pair-alice-{suffix}"),
        base + 1,
        base + 101,
        "",
    )
    .await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    let bob = start_instance(
        &binary,
        &format!("pair-bob-{suffix}"),
        base + 2,
        base + 102,
        &format!("bootstrap_peers = [\"127.0.0.1:{}\"]", base + 101),
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
    let binary = find_x0xd_binary();
    let suffix = rand::random::<u16>();

    // Rolling start: each node needs time for its QUIC listener to bind and
    // mDNS/bootstrap to propagate before the next node comes up. Starting
    // all three simultaneously causes connection races and mesh instability.

    eprintln!("[cluster] starting alice...");
    let alice = start_instance(&binary, &format!("test-alice-{suffix}"), 19101, 19001, "").await;

    eprintln!(
        "[cluster] waiting {}s for alice to stabilise before starting bob...",
        ROLLING_START_DELAY.as_secs()
    );
    tokio::time::sleep(ROLLING_START_DELAY).await;

    eprintln!("[cluster] starting bob (bootstraps to alice)...");
    let bob = start_instance(
        &binary,
        &format!("test-bob-{suffix}"),
        19102,
        19002,
        "bootstrap_peers = [\"127.0.0.1:19001\"]",
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
        19103,
        19003,
        "bootstrap_peers = [\"127.0.0.1:19001\"]",
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
    // From tests/harness/, the project root is ../../
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let binary = PathBuf::from(manifest_dir).join("../../target/release/x0xd");
    if binary.exists() {
        return binary;
    }
    // Try from project root directly
    let alt = PathBuf::from(manifest_dir).join("target/release/x0xd");
    if alt.exists() {
        return alt;
    }
    panic!(
        "x0xd binary not found. Build first: cargo build --release --bin x0xd\n\
         Searched: {}, {}",
        binary.display(),
        alt.display()
    );
}

async fn start_instance(
    binary: &PathBuf,
    name: &str,
    api_port: u16,
    bind_port: u16,
    bootstrap: &str,
) -> AgentInstance {
    let config_dir = std::env::temp_dir().join(format!("x0x-test-{name}"));
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
         {bootstrap}\n",
        config_dir.display()
    );
    std::fs::write(&config_path, &config_content).expect("write config");

    let process = Command::new(binary)
        .arg("--config")
        .arg(&config_path)
        .arg("--name")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("Failed to start x0xd {name}: {e}"));

    // Wrap the Child in an AgentInstance immediately so that Drop kills
    // the process if anything below panics (health timeout, token read, etc.).
    // We'll fill in api_token once we have it.
    let api_addr = format!("127.0.0.1:{api_port}");
    let mut instance = AgentInstance {
        process,
        name: name.to_string(),
        api_addr: api_addr.clone(),
        api_token: String::new(), // placeholder — filled below
        _data_dir: config_dir.clone(),
    };

    // Wait for health — if this panics, `instance` is dropped, killing the process.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let client = reqwest::Client::new();
    loop {
        if let Ok(resp) = client.get(format!("http://{api_addr}/health")).send().await {
            if resp.status().is_success() {
                break;
            }
        }
        if tokio::time::Instant::now() > deadline {
            // instance drops here, killing the process
            panic!("x0xd {name} did not become healthy within 30s");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Read API token — if this panics, `instance` is dropped, killing the process.
    let token_file = config_dir.join("api-token");
    let api_token = if token_file.exists() {
        std::fs::read_to_string(&token_file)
            .expect("read api-token")
            .trim()
            .to_string()
    } else {
        // Try platform-specific data dir
        let data_dir = if cfg!(target_os = "macos") {
            dirs::home_dir()
                .expect("home dir")
                .join("Library/Application Support")
                .join(format!("x0x-{name}"))
        } else {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(format!("x0x-{name}"))
        };
        let alt_token = data_dir.join("api-token");
        std::fs::read_to_string(&alt_token)
            .unwrap_or_else(|_| panic!("Cannot find api-token for {name}"))
            .trim()
            .to_string()
    };

    instance.api_token = api_token;
    instance
}
