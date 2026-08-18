//! Shared x0xd launcher for daemon integration tests.
//!
//! Starts a fresh daemon per test with an isolated temp data dir, a unique
//! instance-scoped identity dir, and update checks disabled for determinism.

#![allow(clippy::expect_used, clippy::panic)]

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::LazyLock;
use std::time::Duration;
use tempfile::TempDir;

/// A private gossip-plane id shared by every fixture in this test process
/// (#337). Nextest runs each test in its own process, so this is effectively
/// per-test: fixtures a single test starts share a plane and can connect, while
/// other tests and ambient daemons are isolated. Computed once per process.
fn process_gossip_plane_id() -> &'static str {
    static PLANE_ID: LazyLock<String> =
        LazyLock::new(|| format!("x0x-test-{}", rand::random::<u32>()));
    PLANE_ID.as_str()
}

/// Per-test x0xd daemon fixture.
pub struct DaemonFixture {
    process: Child,
    api_addr: String,
    api_token: String,
    tempdir: TempDir,
    identity_dir: PathBuf,
}

#[allow(dead_code)]
impl DaemonFixture {
    /// Start a daemon with a unique instance name derived from `prefix`.
    pub async fn start(prefix: &str) -> Self {
        Self::start_with_config(prefix, "").await
    }

    /// Start a daemon with extra TOML config appended to the generated config.
    pub async fn start_with_config(prefix: &str, extra_config: &str) -> Self {
        let name = format!("{prefix}-{}", rand::random::<u32>());
        let binary = find_x0xd_binary();
        assert!(binary.exists(), "Build x0xd first: cargo build --bin x0xd");

        let tempdir = TempDir::new().expect("temp dir");
        let config_path = tempdir.path().join("config.toml");
        // Base keys; `bootstrap_peers` is suppressed when `extra_config`
        // already supplies one to avoid TOML duplicate-key parse errors.
        let extra_has_bootstrap = extra_config
            .lines()
            .any(|l| l.trim_start().starts_with("bootstrap_peers"));
        let bootstrap_line = if extra_has_bootstrap {
            ""
        } else {
            "bootstrap_peers = []\n"
        };
        // Hermetic gossip plane (#337): an unset `network_id` resolves to the
        // PROD plane, which namespaces ant-quic's mDNS — so a fixture advertises
        // on the prod plane's LAN discovery and auto-connects to any live x0xd
        // on the machine (e.g. a running app daemon). Give fixtures a private
        // plane unless the caller set one.
        //
        // The plane is per-PROCESS, not per-fixture: nextest runs each test in
        // its own process, so all fixtures a single test starts share one plane
        // and can still discover/connect to each other (e.g. bob as alice's
        // bootstrap peer), while a different test process and any ambient daemon
        // stay on different planes. A per-fixture plane would wrongly isolate the
        // two daemons of a pairing test from each other. Same suppression shape
        // as `bootstrap_peers` above: a duplicate TOML key is a parse error, and
        // this lets a caller override the plane deliberately.
        let extra_has_network_id = extra_config
            .lines()
            .any(|l| l.trim_start().starts_with("network_id"));
        let network_line = if extra_has_network_id {
            String::new()
        } else {
            format!("network_id = \"{}\"\n", process_gossip_plane_id())
        };
        let mut config = format!(
            "bind_address = \"0.0.0.0:0\"\napi_address = \"127.0.0.1:0\"\ndata_dir = \"{}\"\nlog_level = \"warn\"\n{}{}instance_name = \"{}\"\n",
            tempdir.path().display(),
            bootstrap_line,
            network_line,
            name,
        );
        if !extra_config.trim().is_empty() {
            config.push_str(extra_config);
            if !extra_config.ends_with('\n') {
                config.push('\n');
            }
        }
        std::fs::write(&config_path, config).expect("write config");

        let identity_dir = dirs::home_dir()
            .expect("home dir")
            .join(format!(".x0x-{name}"));

        let mut process_cmd = Command::new(&binary);
        process_cmd
            .arg("--config")
            .arg(&config_path)
            .arg("--skip-update-check")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // `Command` inherits the parent environment by default, so `RUST_LOG`
        // and `X0X_LOG_DIR` set in the test parent's env reach the daemon
        // without explicit forwarding. The single non-redundant behavior
        // here is the `X0X_TEST_LOG_DIR` alias: when set, map it to the
        // daemon's actual log-dir env var so test scripts don't need to
        // know the daemon's variable name. When neither is set, the
        // daemon behaves exactly as before.
        if let Some(v) = std::env::var_os("X0X_TEST_LOG_DIR") {
            process_cmd.env("X0X_LOG_DIR", v);
        }
        let process = process_cmd.spawn().expect("Failed to start x0xd");

        let mut fixture = Self {
            process,
            api_addr: String::new(),
            api_token: String::new(),
            tempdir,
            identity_dir,
        };

        fixture.wait_for_startup().await;
        fixture
    }

    async fn wait_for_startup(&mut self) {
        let port_file = self.port_file();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        self.api_addr = loop {
            if tokio::time::Instant::now() > deadline {
                panic!("Timeout waiting for port file");
            }
            if let Ok(addr) = std::fs::read_to_string(&port_file) {
                let trimmed = addr.trim();
                if let Ok(addr) = trimmed.parse::<std::net::SocketAddr>() {
                    break addr.to_string();
                }
                if let Ok(port) = trimmed.parse::<u16>() {
                    break format!("127.0.0.1:{port}");
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };

        let client = reqwest::Client::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if tokio::time::Instant::now() > deadline {
                panic!("Timeout waiting for health");
            }
            if let Ok(resp) = client
                .get(format!("http://{}/health", self.api_addr))
                .send()
                .await
            {
                if resp.status().is_success() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        let token_file = self.token_file();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        self.api_token = loop {
            if let Ok(token) = std::fs::read_to_string(&token_file) {
                let token = token.trim().to_string();
                if !token.is_empty() {
                    break token;
                }
            }
            if tokio::time::Instant::now() > deadline {
                panic!("Timeout waiting for api-token file");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
    }

    /// Full HTTP URL for `path`.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.api_addr, path)
    }

    /// Exchange the durable API token for a short-lived browser session token
    /// (#127 / WS1.6). Session tokens are the only kind accepted via `?token=`
    /// query strings on WS/SSE endpoints.
    pub async fn session_token(&self) -> String {
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/auth/session", self.api_addr))
            .header(AUTHORIZATION, self.auth_header())
            .send()
            .await
            .expect("POST /auth/session failed");
        let json: serde_json::Value = resp.json().await.expect("/auth/session response json");
        json["session_token"]
            .as_str()
            .expect("session_token field")
            .to_string()
    }

    /// Full WS URL for `path` with a short-lived session `?token=` attached
    /// (#127 / WS1.6). The durable API token is no longer accepted in query
    /// strings, so the WS handshake must use a session token.
    pub async fn ws_url(&self, path: &str) -> String {
        let session = self.session_token().await;
        format!("ws://{}{}?token={session}", self.api_addr, path)
    }

    /// Bearer token header value as a string.
    pub fn auth_header(&self) -> String {
        format!("Bearer {}", self.api_token)
    }

    /// Authenticated reqwest client with a configurable timeout.
    pub fn authed_client(&self, timeout: Duration) -> reqwest::Client {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&self.auth_header()).expect("valid bearer header"),
        );
        reqwest::Client::builder()
            .timeout(timeout)
            .default_headers(headers)
            .build()
            .expect("build authenticated client")
    }

    /// Unauthenticated reqwest client with a configurable timeout.
    pub fn client(timeout: Duration) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("build client")
    }

    /// API address written by x0xd (host:port).
    pub fn api_addr(&self) -> &str {
        &self.api_addr
    }

    /// Raw API token.
    pub fn api_token(&self) -> &str {
        &self.api_token
    }

    /// `<data_dir>/api.port` path.
    pub fn port_file(&self) -> PathBuf {
        self.tempdir.path().join("api.port")
    }

    /// `<data_dir>/api-token` path.
    pub fn token_file(&self) -> PathBuf {
        self.tempdir.path().join("api-token")
    }

    /// Temp data dir used for this daemon.
    pub fn data_dir(&self) -> &Path {
        self.tempdir.path()
    }

    /// Poll child process exit status.
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.process.try_wait()
    }
}

impl Drop for DaemonFixture {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        let _ = std::fs::remove_dir_all(&self.identity_dir);
    }
}

fn find_x0xd_binary() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cargo_test_binary = option_env!("CARGO_BIN_EXE_x0xd").map(PathBuf::from);
    let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    let mut candidates = Vec::new();
    if let Some(path) = cargo_test_binary {
        candidates.push(path);
    }
    candidates.extend([
        manifest_dir.join("target/release/x0xd"),
        manifest_dir.join("../../target/release/x0xd"),
        current_dir.join("target/release/x0xd"),
        manifest_dir.join("target/debug/x0xd"),
        manifest_dir.join("../../target/debug/x0xd"),
        current_dir.join("target/debug/x0xd"),
    ]);

    for candidate in candidates {
        if candidate.exists() {
            return candidate;
        }
    }

    manifest_dir.join("target/release/x0xd")
}
