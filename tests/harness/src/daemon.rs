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
    diagnostic_capture: Option<PathBuf>,
    diagnostic_reaped: bool,
}

/// Opt-in cleanup observations remain available even when retaining them fails.
#[derive(Clone, Debug, serde::Serialize)]
pub struct DiagnosticCleanup {
    pub pid: u32,
    pub reaped: bool,
    pub deliberate_termination: Option<bool>,
    pub exit: Option<String>,
    pub capture_complete: bool,
    pub identity_removed: bool,
    pub errors: Vec<&'static str>,
}

impl DiagnosticCleanup {
    /// Remove only the retained identity child, after this exact child was reaped.
    pub(crate) fn remove_identity_directory(&mut self, identity_dir: &Path) {
        if self.reaped {
            match std::fs::remove_dir_all(identity_dir) {
                Ok(()) => self.identity_removed = true,
                Err(_) => self.errors.push("CHILD_IDENTITY_CLEANUP_IO"),
            }
        }
    }
}

/// Encode the final identity path without filesystem access or lossy substitution.
pub(crate) fn encode_diagnostic_identity_path(identity_dir: &Path) -> std::io::Result<String> {
    let identity_text = identity_dir.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "diagnostic identity path is not UTF-8",
        )
    })?;
    serde_json::to_string(identity_text).map_err(std::io::Error::other)
}

/// Prepare owned identity storage and its exact config without starting a process.
/// The existing data root remains unchanged; only the identity anchor is resolved.
pub(crate) fn prepare_diagnostic_identity(
    data_dir: &Path,
    name: &str,
    plane: &str,
    validate_config: fn(&str) -> std::io::Result<()>,
) -> std::io::Result<(PathBuf, String)> {
    let identity_dir = data_dir.canonicalize()?.join("identity");
    let identity_value = encode_diagnostic_identity_path(&identity_dir)?;
    let config = format!(
        r#"bind_address = "0.0.0.0:0"
api_address = "127.0.0.1:0"
data_dir = {:?}
identity_dir = {identity_value}
log_level = "warn"
bootstrap_peers = []
network_id = {:?}
instance_name = {:?}
"#,
        data_dir.to_string_lossy(),
        plane,
        name,
    );
    // Validate the entire exact text, including inherited data_dir formatting,
    // before creating anything. The real caller supplies the DaemonConfig parser.
    validate_config(&config)?;
    // This fixed child belongs to the existing fresh TempDir. Reject any collision.
    std::fs::create_dir(&identity_dir)?;
    Ok((identity_dir, config))
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
            diagnostic_capture: None,
            diagnostic_reaped: false,
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

    /// PID of the daemon child process (black-hole / signal tests, #368).
    pub fn pid(&self) -> u32 {
        self.process.id()
    }

    /// Poll child process exit status.
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.process.try_wait()
    }
}

impl Drop for DaemonFixture {
    fn drop(&mut self) {
        if self.diagnostic_capture.is_some() {
            // The diagnostic explicitly reaps before success. Cancellation must
            // never block indefinitely in Drop or manufacture a reap receipt.
            if !self.diagnostic_reaped {
                let _ = self.process.kill();
                let _ = self.process.try_wait();
            }
            return;
        }
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

#[allow(dead_code)]
impl DaemonFixture {
    /// Opt-in #287 capture. Returns Child ownership before asynchronous startup.
    /// The caller supplies an exclusive private directory; defaults above stay null.
    pub fn spawn_diagnostic(
        directory: &Path,
        plane: &str,
        hash_binary: fn(&Path) -> std::io::Result<String>,
        validate_config: fn(&str) -> std::io::Result<()>,
    ) -> std::io::Result<Self> {
        use std::io::Write;
        let name = format!("ws287-{}", rand::random::<u64>());
        let tempdir = tempfile::Builder::new()
            .prefix("data-")
            .tempdir_in(directory)?;
        let config_path = tempdir.path().join("config.toml");
        let (identity_dir, config) =
            prepare_diagnostic_identity(tempdir.path(), &name, plane, validate_config)?;
        diagnostic_file(&config_path)?.write_all(config.as_bytes())?;
        let binary = find_x0xd_binary().canonicalize()?;
        let binary_hash = hash_binary(&binary)?;
        let stdout = diagnostic_file(&directory.join("daemon.stdout"))?;
        let stderr = diagnostic_file(&directory.join("daemon.stderr"))?;
        let process = Command::new(&binary)
            .arg("--config")
            .arg(&config_path)
            .arg("--skip-update-check")
            .stdout(stdout)
            .stderr(stderr)
            .spawn()?;
        let pid = process.id();
        let fixture = Self {
            process,
            api_addr: String::new(),
            api_token: String::new(),
            tempdir,
            identity_dir,
            diagnostic_capture: Some(directory.to_owned()),
            diagnostic_reaped: false,
        };
        // If this write fails, fixture Drop kills only this child; no success is credited.
        let record = serde_json::json!({"schema":"x0x.issue287-daemon/1", "pid":pid,
            "binary_path":binary, "binary_sha256":binary_hash, "phase":"spawned",
            "same_build_binding":"UNVERIFIED_EXTERNAL_CUSTODY"});
        serde_json::to_writer(diagnostic_file(&directory.join("spawn.json"))?, &record)?;
        Ok(fixture)
    }

    /// Entire readiness sequence is bounded by the diagnostic's absolute deadline.
    pub async fn diagnostic_ready(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<(), &'static str> {
        let client = Self::client(Duration::from_secs(1));
        loop {
            if self.try_wait().map_err(|_| "CHILD_STATE_IO")?.is_some() {
                return Err("SETUP_CHILD_EXIT");
            }
            if let Ok(text) = std::fs::read_to_string(self.port_file()) {
                if let Ok(addr) = text.trim().parse::<std::net::SocketAddr>() {
                    self.api_addr = addr.to_string();
                } else if let Ok(port) = text.trim().parse::<u16>() {
                    self.api_addr = format!("127.0.0.1:{port}");
                }
            }
            if !self.api_addr.is_empty() {
                let probe = async {
                    let response = client.get(self.url("/health")).send().await.ok()?;
                    if !response.status().is_success() {
                        return None;
                    }
                    response.bytes().await.ok()?;
                    let token = std::fs::read_to_string(self.token_file()).ok()?;
                    if token.trim().is_empty() {
                        return None;
                    }
                    Some(token.trim().to_owned())
                };
                match tokio::time::timeout_at(deadline, probe).await {
                    Ok(Some(token)) => {
                        self.api_token = token;
                        return Ok(());
                    }
                    Err(_) => return Err("SETUP_DEADLINE"),
                    Ok(None) => {}
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("SETUP_DEADLINE");
            }
            tokio::time::sleep_until(
                deadline.min(tokio::time::Instant::now() + Duration::from_millis(100)),
            )
            .await;
        }
    }

    /// A snapshot of this exact Child, never a PID search or a service proxy.
    pub fn diagnostic_child(&mut self) -> std::io::Result<serde_json::Value> {
        let status = self.try_wait()?;
        Ok(
            serde_json::json!({"pid":self.pid(), "alive":status.is_none(),
            "exit":status.map(|s| s.to_string())}),
        )
    }

    /// Explicit bounded cleanup before Drop; observed status survives later I/O failures.
    pub async fn diagnostic_finish(&mut self, deadline: tokio::time::Instant) -> DiagnosticCleanup {
        let mut receipt = DiagnosticCleanup {
            pid: self.pid(),
            reaped: false,
            deliberate_termination: None,
            exit: None,
            capture_complete: false,
            identity_removed: false,
            errors: Vec::new(),
        };
        match self.diagnostic_reap(deadline).await {
            Ok((status, deliberate)) => {
                self.diagnostic_reaped = true;
                receipt.reaped = true;
                receipt.deliberate_termination = Some(deliberate);
                receipt.exit = Some(status.to_string());
            }
            Err(code) => receipt.errors.push(code),
        }
        // These fallible actions cannot erase the already observed Child status.
        if let Some(directory) = &self.diagnostic_capture {
            let capture = (|| -> std::io::Result<()> {
                let file = diagnostic_file(&directory.join("cleanup.json"))?;
                serde_json::to_writer(
                    &file,
                    &serde_json::json!({"pid":receipt.pid,
                    "reaped":receipt.reaped,"deliberate_termination":receipt.deliberate_termination,
                    "exit":receipt.exit}),
                )?;
                file.sync_all()
            })();
            match capture {
                Ok(()) => receipt.capture_complete = true,
                Err(_) => receipt.errors.push("CHILD_CLEANUP_CAPTURE_IO"),
            }
        } else {
            receipt.errors.push("CHILD_CLEANUP_CAPTURE_MISSING");
        }
        receipt.remove_identity_directory(&self.identity_dir);
        receipt
    }

    async fn diagnostic_reap(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<(ExitStatus, bool), &'static str> {
        // try_wait already reaps an exited child: retain that exact observation.
        if let Some(status) = self.try_wait().map_err(|_| "CHILD_STATE_IO")? {
            return Ok((status, false));
        }
        if self.process.kill().is_err() {
            return self
                .try_wait()
                .map_err(|_| "CHILD_STATE_IO")?
                .map(|status| (status, false))
                .ok_or("CHILD_KILL_IO");
        }
        loop {
            if let Some(status) = self.try_wait().map_err(|_| "CHILD_STATE_IO")? {
                return Ok((status, true));
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("CHILD_REAP_DEADLINE");
            }
            tokio::time::sleep_until(
                deadline.min(tokio::time::Instant::now() + Duration::from_millis(20)),
            )
            .await;
        }
    }
}

#[allow(dead_code)]
pub fn diagnostic_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
