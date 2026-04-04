//! Shared x0xd launcher for ignored integration tests.
//!
//! Starts a fresh daemon per test with an isolated temp data dir, a unique
//! instance-scoped identity dir, and update checks disabled for determinism.

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;
use tempfile::TempDir;

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
        assert!(
            binary.exists(),
            "Build x0xd first: cargo build --release --bin x0xd"
        );

        let tempdir = TempDir::new().expect("temp dir");
        let config_path = tempdir.path().join("config.toml");
        let mut config = format!(
            "bind_address = \"0.0.0.0:0\"\napi_address = \"127.0.0.1:0\"\ndata_dir = \"{}\"\nlog_level = \"warn\"\nbootstrap_peers = []\ninstance_name = \"{}\"\n",
            tempdir.path().display(),
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

        let process = Command::new(&binary)
            .arg("--config")
            .arg(&config_path)
            .arg("--skip-update-check")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start x0xd");

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

    /// Full WS URL for `path` with `?token=` attached.
    pub fn ws_url(&self, path: &str) -> String {
        format!("ws://{}{}?token={}", self.api_addr, path, self.api_token)
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
    let candidates = [
        manifest_dir.join("target/release/x0xd"),
        manifest_dir.join("../../target/release/x0xd"),
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("target/release/x0xd"),
    ];

    for candidate in candidates {
        if candidate.exists() {
            return candidate;
        }
    }

    manifest_dir.join("target/release/x0xd")
}
