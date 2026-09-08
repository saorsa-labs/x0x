//! Ignored two-daemon Home onboarding acceptance preparation (#447).
//!
//! Runtime execution is admitted separately under the reviewed network-namespace
//! wrapper. The test requires explicit absolute paths to the freshly built
//! `x0xd` and `x0x` binaries; it never falls back to `PATH` or another target dir.

use anyhow::{ensure, Context, Result};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const ONBOARDING_TIMEOUT: Duration = Duration::from_secs(120);
const DIAGNOSTIC_TEST: &str = "home_onboarding_single_announce_restart";
const CHILD_LABELS: [&str; 4] = [
    "owner_initial",
    "joiner_initial",
    "owner_restart",
    "joiner_restart",
];

#[derive(Clone)]
struct ChildObservation {
    started: bool,
    cleanup: &'static str,
    exit_code: Option<i32>,
    signaled: bool,
    escalation: &'static str,
}

struct DiagnosticState {
    phase: &'static str,
    result: &'static str,
    failure_kind: &'static str,
    last_http_status: Option<u16>,
    cli_exit_code: Option<i32>,
    cli_signaled: bool,
    children: [ChildObservation; 4],
}

#[derive(Clone)]
struct TestDiagnostic {
    path: Arc<PathBuf>,
    run_nonce: Arc<String>,
    source_head: Arc<String>,
    source_tree: Arc<String>,
    state: Arc<Mutex<DiagnosticState>>,
}

impl TestDiagnostic {
    fn new() -> Result<Self> {
        let path = PathBuf::from(
            std::env::var_os("X0X_TEST_HOME_RECEIPT")
                .context("X0X_TEST_HOME_RECEIPT is required")?,
        );
        let run_nonce = std::env::var("X0X_TEST_RUN_NONCE")?;
        let source_head = std::env::var("X0X_TEST_SOURCE_HEAD")?;
        let source_tree = std::env::var("X0X_TEST_SOURCE_TREE")?;
        Self::new_bound(path, run_nonce, source_head, source_tree)
    }

    fn new_bound(
        path: PathBuf,
        run_nonce: String,
        source_head: String,
        source_tree: String,
    ) -> Result<Self> {
        ensure!(
            path.is_absolute(),
            "diagnostic receipt path must be absolute"
        );
        ensure!(
            path.parent().is_some_and(Path::is_dir),
            "diagnostic receipt parent must exist"
        );
        let nonce_parts = run_nonce.split(':').collect::<Vec<_>>();
        ensure!(
            nonce_parts.len() == 2
                && nonce_parts
                    .iter()
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())),
            "invalid public run nonce"
        );
        ensure!(is_lower_hex(&source_head, 40) && is_lower_hex(&source_tree, 40));
        let empty = ChildObservation {
            started: false,
            cleanup: "not_started",
            exit_code: None,
            signaled: false,
            escalation: "none",
        };
        let diagnostic = Self {
            path: Arc::new(path),
            run_nonce: Arc::new(run_nonce),
            source_head: Arc::new(source_head),
            source_tree: Arc::new(source_tree),
            state: Arc::new(Mutex::new(DiagnosticState {
                phase: "fixture_setup",
                result: "running",
                failure_kind: "none",
                last_http_status: None,
                cli_exit_code: None,
                cli_signaled: false,
                children: [empty.clone(), empty.clone(), empty.clone(), empty],
            })),
        };
        diagnostic.persist(true)?;
        Ok(diagnostic)
    }

    fn persist(&self, initial: bool) -> Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("diagnostic lock poisoned"))?;
        let children = CHILD_LABELS
            .iter()
            .zip(state.children.iter())
            .map(|(label, child)| {
                (
                    (*label).to_string(),
                    json!({
                        "started": child.started,
                        "cleanup": child.cleanup,
                        "exit_code": child.exit_code,
                        "signaled": child.signaled,
                        "escalation": child.escalation,
                    }),
                )
            })
            .collect::<serde_json::Map<String, Value>>();
        let value = json!({
            "schema": 1,
            "test": DIAGNOSTIC_TEST,
            "run_nonce": self.run_nonce.as_str(),
            "source_head": self.source_head.as_str(),
            "source_tree": self.source_tree.as_str(),
            "entered": true,
            "phase": state.phase,
            "result": state.result,
            "failure_kind": state.failure_kind,
            "last_http_status": state.last_http_status,
            "cli_exit_code": state.cli_exit_code,
            "cli_signaled": state.cli_signaled,
            "children": children,
        });
        if initial {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.path.as_ref())
                .context("create fresh diagnostic receipt")?;
            serde_json::to_writer(&mut file, &value)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        } else {
            let temporary = self.path.with_extension("json.next");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .context("create fresh diagnostic update")?;
            serde_json::to_writer(&mut file, &value)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            std::fs::rename(&temporary, self.path.as_ref())?;
        }
        Ok(())
    }

    fn update(&self, change: impl FnOnce(&mut DiagnosticState)) -> Result<()> {
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("diagnostic lock poisoned"))?;
            change(&mut state);
        }
        self.persist(false)
    }

    fn phase(&self, phase: &'static str) -> Result<()> {
        self.update(|state| {
            state.phase = phase;
            state.last_http_status = None;
        })
    }

    fn http_status(&self, status: StatusCode) -> Result<()> {
        self.update(|state| state.last_http_status = Some(status.as_u16()))
    }

    fn clear_http_status(&self) -> Result<()> {
        self.update(|state| state.last_http_status = None)
    }

    fn cli_status(&self, status: std::process::ExitStatus) -> Result<()> {
        self.update(|state| {
            state.cli_exit_code = status.code();
            state.cli_signaled = status.code().is_none();
        })
    }

    fn child_started(&self, label: &'static str) -> Result<()> {
        let index = child_index(label)?;
        self.update(|state| {
            state.children[index].started = true;
            state.children[index].cleanup = "running";
        })
    }

    fn child_reaped(
        &self,
        label: &'static str,
        status: std::process::ExitStatus,
        escalation: &'static str,
    ) -> Result<()> {
        let index = child_index(label)?;
        self.update(|state| {
            state.children[index].cleanup = "reaped";
            state.children[index].exit_code = status.code();
            state.children[index].signaled = status.code().is_none();
            state.children[index].escalation = escalation;
        })
    }

    fn child_cleanup_failed(&self, label: &'static str, escalation: &'static str) {
        if let Ok(index) = child_index(label) {
            let _ = self.update(|state| {
                state.children[index].cleanup = "cleanup_failed";
                state.children[index].escalation = escalation;
            });
        }
    }

    fn finish(&self, passed: bool) -> Result<()> {
        self.update(|state| {
            state.result = if passed { "passed" } else { "failed" };
            state.failure_kind = if passed { "none" } else { "stage_failed" };
            if passed {
                state.phase = "complete";
            }
        })
    }

    fn fail_if_running(&self) {
        let running = self
            .state
            .lock()
            .map(|state| state.result == "running")
            .unwrap_or(false);
        if running {
            let _ = self.finish(false);
        }
    }
}

struct DiagnosticGuard(TestDiagnostic);

impl Drop for DiagnosticGuard {
    fn drop(&mut self) {
        self.0.fail_if_running();
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn child_index(label: &str) -> Result<usize> {
    CHILD_LABELS
        .iter()
        .position(|candidate| *candidate == label)
        .with_context(|| format!("unknown diagnostic child label {label}"))
}

struct ReservedPorts {
    api: TcpListener,
    quic: UdpSocket,
}

impl ReservedPorts {
    fn new() -> Result<Self> {
        Ok(Self {
            api: TcpListener::bind(("127.0.0.1", 0)).context("reserve API port")?,
            quic: UdpSocket::bind(("127.0.0.1", 0)).context("reserve QUIC port")?,
        })
    }

    fn addresses(&self) -> Result<(SocketAddr, SocketAddr)> {
        Ok((self.api.local_addr()?, self.quic.local_addr()?))
    }
}

struct OwnedDaemon {
    child: Option<Child>,
    label: &'static str,
    api: SocketAddr,
    token: String,
    data_dir: PathBuf,
    diagnostic: TestDiagnostic,
}

impl OwnedDaemon {
    async fn start(
        binary: &Path,
        config: &Path,
        api: SocketAddr,
        data_dir: PathBuf,
        label: &'static str,
        diagnostic: TestDiagnostic,
    ) -> Result<Self> {
        let child = Command::new(binary)
            .args(["--config", &config.display().to_string()])
            .args(["--skip-update-check", "--no-port-mapping"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawn owned daemon {}", binary.display()))?;
        let mut daemon = Self {
            child: Some(child),
            label,
            api,
            token: String::new(),
            data_dir,
            diagnostic,
        };
        daemon.record_started()?;
        daemon.wait_ready().await?;
        Ok(daemon)
    }

    fn record_started(&self) -> Result<()> {
        self.diagnostic.child_started(self.label)
    }

    async fn wait_ready(&mut self) -> Result<()> {
        let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()?;
        loop {
            ensure!(
                tokio::time::Instant::now() < deadline,
                "owned daemon readiness deadline expired"
            );
            ensure!(self.is_running()?, "owned daemon exited before readiness");
            if let (Ok(advertised), Ok(token)) = (
                std::fs::read_to_string(self.data_dir.join("api.port")),
                std::fs::read_to_string(self.data_dir.join("api-token")),
            ) {
                let token = token.trim();
                if advertised_matches(&advertised, self.api) && !token.is_empty() {
                    let probes = async {
                        self.diagnostic.clear_http_status()?;
                        let health = client
                            .get(format!("http://{}/health", self.api))
                            .send()
                            .await;
                        let Ok(health) = health else {
                            return Ok::<bool, anyhow::Error>(false);
                        };
                        self.diagnostic.http_status(health.status())?;
                        if health.status() != StatusCode::OK {
                            return Ok(false);
                        }
                        self.diagnostic.clear_http_status()?;
                        let agent = client
                            .get(format!("http://{}/agent", self.api))
                            .bearer_auth(token)
                            .send()
                            .await;
                        let Ok(agent) = agent else {
                            return Ok(false);
                        };
                        self.diagnostic.http_status(agent.status())?;
                        Ok(agent.status() == StatusCode::OK)
                    };
                    if let Ok(Ok(true)) = tokio::time::timeout_at(deadline, probes).await {
                        if readiness_success_allowed(
                            tokio::time::Instant::now(),
                            deadline,
                            self.is_running()?,
                        ) {
                            self.token = token.to_owned();
                            return Ok(());
                        }
                    }
                }
            }
            let _ =
                tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(100)))
                    .await;
        }
    }

    fn is_running(&mut self) -> Result<bool> {
        Ok(self
            .child
            .as_mut()
            .context("owned child already reaped")?
            .try_wait()?
            .is_none())
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<(StatusCode, Value)> {
        self.diagnostic.clear_http_status()?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()?;
        let mut request = client
            .request(method, format!("http://{}{}", self.api, path))
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await?;
        let status = response.status();
        self.diagnostic.http_status(status)?;
        let body = response.json().await.context("decode API JSON")?;
        Ok((status, body))
    }

    async fn request_before(
        &self,
        deadline: tokio::time::Instant,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<(StatusCode, Value)> {
        ensure_before_deadline(deadline, "before API request")?;
        let response = tokio::time::timeout_at(deadline, self.request(method, path, body))
            .await
            .with_context(|| format!("onboarding deadline expired during {path}"))??;
        ensure_before_deadline(deadline, "after API response")?;
        Ok(response)
    }

    async fn get(&self, path: &str) -> Result<Value> {
        let (status, body) = self.request(reqwest::Method::GET, path, None).await?;
        ensure!(
            status == StatusCode::OK,
            "GET {path} returned {status}: {body}"
        );
        Ok(body)
    }

    async fn get_before(&self, deadline: tokio::time::Instant, path: &str) -> Result<Value> {
        let (status, body) = self
            .request_before(deadline, reqwest::Method::GET, path, None)
            .await?;
        ensure!(
            status == StatusCode::OK,
            "GET {path} returned {status}: {body}"
        );
        Ok(body)
    }

    async fn post(&self, path: &str, body: Value) -> Result<(StatusCode, Value)> {
        self.request(reqwest::Method::POST, path, Some(body)).await
    }

    async fn post_before(
        &self,
        deadline: tokio::time::Instant,
        path: &str,
        body: Value,
    ) -> Result<(StatusCode, Value)> {
        self.request_before(deadline, reqwest::Method::POST, path, Some(body))
            .await
    }

    async fn put(&self, path: &str, body: Value) -> Result<(StatusCode, Value)> {
        self.request(reqwest::Method::PUT, path, Some(body)).await
    }

    async fn stop(&mut self) -> Result<()> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()?;
        self.diagnostic.clear_http_status()?;
        let shutdown = client
            .post(format!("http://{}/shutdown", self.api))
            .bearer_auth(&self.token)
            .send()
            .await;
        if let Ok(response) = shutdown {
            self.diagnostic.http_status(response.status())?;
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while self.is_running()? && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let mut escalation = "none";
        if self.is_running()? {
            self.child.as_mut().context("owned child missing")?.kill()?;
            escalation = "kill";
        }
        let status = match self.child.take().context("owned child missing")?.wait() {
            Ok(status) => status,
            Err(error) => {
                self.diagnostic.child_cleanup_failed(self.label, escalation);
                return Err(error.into());
            }
        };
        self.diagnostic
            .child_reaped(self.label, status, escalation)?;
        ensure!(status.success(), "owned daemon exited with {status}");
        Ok(())
    }
}

fn advertised_matches(contents: &str, expected: SocketAddr) -> bool {
    contents
        .trim()
        .parse::<SocketAddr>()
        .is_ok_and(|advertised| advertised == expected)
}

fn readiness_success_allowed(
    now: tokio::time::Instant,
    deadline: tokio::time::Instant,
    child_running: bool,
) -> bool {
    child_running && now < deadline
}

fn ensure_before_deadline(deadline: tokio::time::Instant, stage: &str) -> Result<()> {
    ensure!(
        tokio::time::Instant::now() < deadline,
        "onboarding deadline expired {stage}"
    );
    Ok(())
}

async fn sleep_before(deadline: tokio::time::Instant) -> Result<()> {
    tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(250)))
        .await
        .context("onboarding deadline expired while polling")?;
    ensure_before_deadline(deadline, "after polling delay")
}

impl Drop for OwnedDaemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let (escalation, waited) = match child.try_wait() {
                Ok(Some(status)) => ("none", Ok(status)),
                Ok(None) => {
                    let escalation = if child.kill().is_ok() {
                        "kill"
                    } else {
                        "kill_failed"
                    };
                    (escalation, child.wait())
                }
                Err(_) => ("kill_failed", child.wait()),
            };
            match waited {
                Ok(status) => {
                    let _ = self.diagnostic.child_reaped(self.label, status, escalation);
                }
                Err(_) => self.diagnostic.child_cleanup_failed(self.label, escalation),
            }
        }
    }
}

fn pinned_binary(variable: &str, expected_name: &str) -> Result<PathBuf> {
    let configured = std::env::var_os(variable)
        .map(PathBuf::from)
        .with_context(|| format!("{variable} must name the reviewed debug binary"))?;
    ensure!(configured.is_absolute(), "{variable} must be absolute");
    let canonical = configured
        .canonicalize()
        .with_context(|| format!("canonicalize {variable}"))?;
    ensure!(canonical.is_file(), "{variable} is not a file");
    ensure!(
        canonical
            .file_name()
            .is_some_and(|name| name == expected_name),
        "{variable} must name {expected_name}"
    );
    Ok(canonical)
}

fn toml_string(path: &Path) -> Result<String> {
    serde_json::to_string(&path.to_string_lossy()).context("encode TOML path")
}

struct NodeConfig<'a> {
    data_dir: &'a Path,
    identity_dir: &'a Path,
    user_key: &'a Path,
    api: SocketAddr,
    quic: SocketAddr,
    bootstrap: &'a [SocketAddr],
    network_id: &'a str,
}

fn write_config(path: &Path, config: &NodeConfig<'_>) -> Result<()> {
    let peers = config
        .bootstrap
        .iter()
        .map(|peer| format!("\"{peer}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let contents = format!(
        "bind_address = \"{}\"\napi_address = \"{}\"\ndata_dir = {}\nidentity_dir = {}\nuser_key_path = {}\nbootstrap_peers = [{peers}]\nnetwork_id = \"{}\"\nport_mapping_enabled = false\nrendezvous_enabled = false\nlog_level = \"warn\"\n",
        config.quic,
        config.api,
        toml_string(config.data_dir)?,
        toml_string(config.identity_dir)?,
        toml_string(config.user_key)?,
        config.network_id,
    );
    std::fs::write(path, contents).context("write owned daemon config")
}

fn string_field<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string field {pointer}"))
}

fn member_is_active(home: &Value, agent_id: &str) -> bool {
    home["members"]
        .as_array()
        .is_some_and(|members| members.iter().any(|member| member["agent_id"] == agent_id))
}

async fn wait_for_active_home(
    daemon: &OwnedDaemon,
    group_id: &str,
    owner_id: &str,
    member_ids: &[&str],
    deadline: tokio::time::Instant,
) -> Result<Value> {
    loop {
        if let Ok(home) = daemon.get_before(deadline, "/home").await {
            let matches = home["group_id"] == group_id
                && home["owner_user_id"] == owner_id
                && home["state"] == "local"
                && member_ids.iter().all(|id| member_is_active(&home, id));
            if matches {
                ensure_before_deadline(deadline, "after active Home observation")?;
                return Ok(home);
            }
        }
        sleep_before(deadline)
            .await
            .context("Home did not converge to active membership")?;
    }
}

fn assert_identity_contract(agent: &Value, profile: &Value, card: &Value) -> Result<()> {
    let agent_id = string_field(agent, "/data/agent_id")?;
    let machine_id = string_field(agent, "/data/machine_id")?;
    let user_id = string_field(agent, "/data/user_id")?;
    ensure!(agent_id.len() == 64 && machine_id.len() == 64 && user_id.len() == 64);
    ensure!(card["card"]["agent_id"] == agent_id);
    ensure!(card["card"]["machine_id"] == machine_id);
    ensure!(card["card"]["user_id"] == user_id);
    ensure!(card["card"]["display_name"] == profile["data"]["display_name"]);
    ensure!(card["card"]["owner_name"] == profile["data"]["human_name"]);
    Ok(())
}

async fn wait_for_owned_peer(
    daemon: &OwnedDaemon,
    owner_user_id: &str,
    peer_agent_id: &str,
    peer_machine_id: &str,
    deadline: tokio::time::Instant,
) -> Result<()> {
    loop {
        if let Ok(roster) = daemon.get_before(deadline, "/owner/agents").await {
            let ready = roster["owner_user_id"] == owner_user_id
                && roster["agents"].as_array().is_some_and(|agents| {
                    agents.iter().any(|agent| {
                        agent["agent_id"] == peer_agent_id
                            && agent["machine_id"] == peer_machine_id
                            && agent["revoked"] == false
                    })
                });
            if ready {
                ensure_before_deadline(deadline, "after owner roster observation")?;
                return Ok(());
            }
        }
        sleep_before(deadline)
            .await
            .context("owner-certified peer readiness did not converge")?;
    }
}

#[derive(Clone, Copy)]
enum CanonicalSide {
    Owner,
    Joiner,
}

fn canonical_side(
    owner: &Value,
    joiner: &Value,
    owner_id: &str,
    joiner_id: &str,
) -> Option<CanonicalSide> {
    let owner_group = owner["group_id"].as_str()?;
    let joiner_group = joiner["group_id"].as_str()?;
    if owner["state"] == "local"
        && joiner["state"] == "adoption_pending"
        && joiner["canonical_group_id"] == owner_group
        && member_is_active(owner, owner_id)
        && member_is_active(joiner, joiner_id)
    {
        Some(CanonicalSide::Owner)
    } else if joiner["state"] == "local"
        && owner["state"] == "adoption_pending"
        && owner["canonical_group_id"] == joiner_group
        && member_is_active(joiner, joiner_id)
        && member_is_active(owner, owner_id)
    {
        Some(CanonicalSide::Joiner)
    } else {
        None
    }
}

async fn wait_for_canonical_home(
    owner: &OwnedDaemon,
    joiner: &OwnedDaemon,
    owner_user_id: &str,
    owner_agent_id: &str,
    joiner_agent_id: &str,
    deadline: tokio::time::Instant,
) -> Result<(CanonicalSide, String)> {
    loop {
        let owner_home = owner.get_before(deadline, "/home").await;
        let joiner_home = joiner.get_before(deadline, "/home").await;
        if let (Ok(owner_home), Ok(joiner_home)) = (owner_home, joiner_home) {
            if owner_home["owner_user_id"] == owner_user_id
                && joiner_home["owner_user_id"] == owner_user_id
            {
                if let Some(side) =
                    canonical_side(&owner_home, &joiner_home, owner_agent_id, joiner_agent_id)
                {
                    let group_id = match side {
                        CanonicalSide::Owner => string_field(&owner_home, "/group_id")?,
                        CanonicalSide::Joiner => string_field(&joiner_home, "/group_id")?,
                    };
                    ensure_before_deadline(deadline, "after canonical Home observation")?;
                    return Ok((side, group_id.to_owned()));
                }
            }
        }
        sleep_before(deadline)
            .await
            .context("owner-sync did not elect one canonical Home")?;
    }
}

async fn run_home_onboarding_scenario(diagnostic: TestDiagnostic) -> Result<()> {
    diagnostic.phase("fixture_setup")?;
    let x0xd = pinned_binary("X0X_TEST_X0XD_BIN", "x0xd")?;
    let x0x = pinned_binary("X0X_TEST_X0X_BIN", "x0x")?;
    let root = TempDir::new().context("create owned fixture root")?;
    let user_key = root.path().join("owner/user.key");
    std::fs::create_dir_all(user_key.parent().context("owner key parent")?)?;
    diagnostic.phase("key_create")?;
    let key_status = Command::new(&x0x)
        .args(["user-id", "create"])
        .arg(&user_key)
        .status()
        .context("create shared owner key with pinned x0x")?;
    diagnostic.cli_status(key_status)?;
    ensure!(key_status.success(), "x0x user-id create failed");

    let owner_ports = ReservedPorts::new()?;
    let joiner_ports = ReservedPorts::new()?;
    let (owner_api, owner_quic) = owner_ports.addresses()?;
    let (joiner_api, joiner_quic) = joiner_ports.addresses()?;
    let plane = format!("home-onboarding-{}", rand::random::<u64>());
    for name in ["owner", "joiner"] {
        std::fs::create_dir_all(root.path().join(name).join("data"))?;
        std::fs::create_dir_all(root.path().join(name).join("identity"))?;
    }
    write_config(
        &root.path().join("owner/config.toml"),
        &NodeConfig {
            data_dir: &root.path().join("owner/data"),
            identity_dir: &root.path().join("owner/identity"),
            user_key: &user_key,
            api: owner_api,
            quic: owner_quic,
            bootstrap: &[],
            network_id: &plane,
        },
    )?;
    write_config(
        &root.path().join("joiner/config.toml"),
        &NodeConfig {
            data_dir: &root.path().join("joiner/data"),
            identity_dir: &root.path().join("joiner/identity"),
            user_key: &user_key,
            api: joiner_api,
            quic: joiner_quic,
            bootstrap: &[owner_quic],
            network_id: &plane,
        },
    )?;

    diagnostic.phase("owner_initial_start")?;
    drop(owner_ports);
    let mut owner = OwnedDaemon::start(
        &x0xd,
        &root.path().join("owner/config.toml"),
        owner_api,
        root.path().join("owner/data"),
        "owner_initial",
        diagnostic.clone(),
    )
    .await?;
    diagnostic.phase("joiner_initial_start")?;
    drop(joiner_ports);
    let mut joiner = OwnedDaemon::start(
        &x0xd,
        &root.path().join("joiner/config.toml"),
        joiner_api,
        root.path().join("joiner/data"),
        "joiner_initial",
        diagnostic.clone(),
    )
    .await?;

    diagnostic.phase("profile_identity")?;
    let (status, _) = owner
        .put(
            "/profile",
            json!({"human_name":"Fixture Owner","display_name":"owner-device","machine_name":"owner-machine"}),
        )
        .await?;
    ensure!(status == StatusCode::OK, "owner profile update failed");
    let (status, _) = joiner
        .put(
            "/profile",
            json!({"human_name":"Fixture Owner","display_name":"joiner-device","machine_name":"joiner-machine"}),
        )
        .await?;
    ensure!(status == StatusCode::OK, "joiner profile update failed");

    let owner_agent = owner.get("/agent").await?;
    let joiner_agent = joiner.get("/agent").await?;
    let owner_id = string_field(&owner_agent, "/data/agent_id")?.to_owned();
    let joiner_id = string_field(&joiner_agent, "/data/agent_id")?.to_owned();
    let owner_machine = string_field(&owner_agent, "/data/machine_id")?.to_owned();
    let joiner_machine = string_field(&joiner_agent, "/data/machine_id")?.to_owned();
    let owner_user = string_field(&owner_agent, "/data/user_id")?.to_owned();
    ensure!(owner_id != joiner_id && owner_machine != joiner_machine);
    ensure!(owner_user == string_field(&joiner_agent, "/data/user_id")?);

    let owner_profile = owner.get("/profile").await?;
    let joiner_profile = joiner.get("/profile").await?;
    let owner_card = owner
        .get("/agent/card?include_local_addresses=true")
        .await?;
    let joiner_card = joiner
        .get("/agent/card?include_local_addresses=true")
        .await?;
    assert_identity_contract(&owner_agent, &owner_profile, &owner_card)?;
    assert_identity_contract(&joiner_agent, &joiner_profile, &joiner_card)?;

    diagnostic.phase("peer_connect")?;
    for (target, card) in [(&owner, &joiner_card), (&joiner, &owner_card)] {
        let (status, body) = target
            .post(
                "/agent/card/import",
                json!({"card": string_field(card, "/link")?, "trust_level":"trusted"}),
            )
            .await?;
        ensure!(status == StatusCode::OK && body["ok"] == true);
    }
    let (status, _) = owner
        .post("/agents/connect", json!({"agent_id":joiner_id}))
        .await?;
    ensure!(status == StatusCode::OK);

    diagnostic.phase("consent_negative")?;
    let (status, _) = joiner
        .post(
            "/announce",
            json!({"include_user_identity":true,"human_consent":false}),
        )
        .await?;
    ensure!(
        status == StatusCode::BAD_REQUEST,
        "consent-negative announce was accepted"
    );
    diagnostic.phase("announce")?;
    let onboarding_deadline = tokio::time::Instant::now() + ONBOARDING_TIMEOUT;
    let mut owner_explicit_announces = 0_u8;
    let mut joiner_explicit_announces = 0_u8;
    for (daemon, count) in [
        (&owner, &mut owner_explicit_announces),
        (&joiner, &mut joiner_explicit_announces),
    ] {
        let (status, body) = daemon
            .post_before(
                onboarding_deadline,
                "/announce",
                json!({"include_user_identity":true,"human_consent":true}),
            )
            .await?;
        ensure!(status == StatusCode::OK && body["include_user_identity"] == true);
        *count += 1;
    }
    ensure!(owner_explicit_announces == 1 && joiner_explicit_announces == 1);
    diagnostic.phase("owner_sync")?;
    wait_for_owned_peer(
        &owner,
        &owner_user,
        &joiner_id,
        &joiner_machine,
        onboarding_deadline,
    )
    .await?;
    wait_for_owned_peer(
        &joiner,
        &owner_user,
        &owner_id,
        &owner_machine,
        onboarding_deadline,
    )
    .await?;

    // Tier-1 is explicitly owner-enrolled and bilateral. Enroll both the
    // local and peer machine on each daemon; the cross entries authorize the
    // dial and inbound stream, while the self entries make the owner device
    // set complete on both sides as documented by the API contract.
    diagnostic.phase("device_enroll")?;
    for (daemon, machines) in [
        (&owner, [&owner_machine, &joiner_machine]),
        (&joiner, [&joiner_machine, &owner_machine]),
    ] {
        for machine_id in machines {
            let (status, body) = daemon
                .post_before(
                    onboarding_deadline,
                    "/sync/devices/enroll",
                    json!({"machine_id":machine_id}),
                )
                .await?;
            ensure!(status == StatusCode::OK && body["ok"] == true);
            ensure!(body["data"]["machine_id"] == machine_id.as_str());
        }
    }

    diagnostic.phase("canonical_home")?;
    let (canonical_side, home_id) = wait_for_canonical_home(
        &owner,
        &joiner,
        &owner_user,
        &owner_id,
        &joiner_id,
        onboarding_deadline,
    )
    .await?;
    let (canonical, adopting, adopting_id, adopting_name) = match canonical_side {
        CanonicalSide::Owner => (&owner, &joiner, &joiner_id, "joiner-device"),
        CanonicalSide::Joiner => (&joiner, &owner, &owner_id, "owner-device"),
    };
    diagnostic.phase("seat_invite")?;
    let (status, renamed) = canonical
        .post_before(
            onboarding_deadline,
            "/home/rename",
            json!({"name":"Fixture Home"}),
        )
        .await?;
    ensure!(status == StatusCode::OK && renamed["ok"] == true);
    let (status, seat) = canonical
        .post_before(
            onboarding_deadline,
            "/home/seat",
            json!({"agent_id":adopting_id}),
        )
        .await?;
    ensure!(status == StatusCode::OK && seat["seated"] == false);
    ensure!(seat["group_id"] == home_id && seat["owner_user_id"] == owner_user);
    let invite = string_field(&seat, "/invite")?.to_owned();

    diagnostic.phase("wrong_owner_negative")?;
    let (status, wrong_pin) = adopting
        .post_before(
            onboarding_deadline,
            "/groups/join",
            json!({"invite":invite,"mode":"home","expected_owner_user_id":"00".repeat(32)}),
        )
        .await?;
    ensure!(status == StatusCode::CONFLICT && wrong_pin["error"] == "owner_mismatch");
    diagnostic.phase("wrong_mode_negative")?;
    let (status, wrong_mode) = adopting
        .post_before(
            onboarding_deadline,
            "/groups/join",
            json!({"invite":invite,"mode":"group"}),
        )
        .await?;
    ensure!(status == StatusCode::CONFLICT && wrong_mode["error"] == "use_home_mode");
    diagnostic.phase("home_join")?;
    let (status, joined) = adopting
        .post_before(
            onboarding_deadline,
            "/groups/join",
            json!({"invite":invite,"display_name":adopting_name,"mode":"home","expected_owner_user_id":owner_user}),
        )
        .await?;
    ensure!(status == StatusCode::OK && joined["group_id"] == home_id);
    ensure!(joined["join_state"] == "pending_authority_commit" || joined["join_state"] == "active");

    diagnostic.phase("active_home")?;
    let _ = wait_for_active_home(
        &owner,
        &home_id,
        &owner_user,
        &[&owner_id, &joiner_id],
        onboarding_deadline,
    )
    .await?;
    let _ = wait_for_active_home(
        &joiner,
        &home_id,
        &owner_user,
        &[&owner_id, &joiner_id],
        onboarding_deadline,
    )
    .await?;
    ensure_before_deadline(onboarding_deadline, "after both active Home observations")?;
    diagnostic.phase("initial_seal")?;
    let (status, sealed) = canonical
        .post(&format!("/groups/{home_id}/state/seal"), json!({}))
        .await?;
    ensure!(status == StatusCode::OK && sealed["ok"] == true);

    diagnostic.phase("initial_stop")?;
    joiner.stop().await?;
    owner.stop().await?;
    diagnostic.phase("owner_restart")?;
    let mut owner = OwnedDaemon::start(
        &x0xd,
        &root.path().join("owner/config.toml"),
        owner_api,
        root.path().join("owner/data"),
        "owner_restart",
        diagnostic.clone(),
    )
    .await?;
    diagnostic.phase("joiner_restart")?;
    let mut joiner = OwnedDaemon::start(
        &x0xd,
        &root.path().join("joiner/config.toml"),
        joiner_api,
        root.path().join("joiner/data"),
        "joiner_restart",
        diagnostic.clone(),
    )
    .await?;
    diagnostic.phase("restart_identity")?;
    let owner_after = owner.get("/agent").await?;
    let joiner_after = joiner.get("/agent").await?;
    ensure!(string_field(&owner_after, "/data/agent_id")? == owner_id);
    ensure!(string_field(&owner_after, "/data/machine_id")? == owner_machine);
    ensure!(string_field(&joiner_after, "/data/agent_id")? == joiner_id);
    ensure!(string_field(&joiner_after, "/data/machine_id")? == joiner_machine);
    diagnostic.phase("restart_home")?;
    let restart_deadline = tokio::time::Instant::now() + ONBOARDING_TIMEOUT;
    let owner_home = wait_for_active_home(
        &owner,
        &home_id,
        &owner_user,
        &[&owner_id, &joiner_id],
        restart_deadline,
    )
    .await?;
    let joiner_home = wait_for_active_home(
        &joiner,
        &home_id,
        &owner_user,
        &[&owner_id, &joiner_id],
        restart_deadline,
    )
    .await?;
    ensure!(owner_home["name"] == "Fixture Home" && joiner_home["name"] == "Fixture Home");
    diagnostic.phase("restart_seal")?;
    let seal_daemon = match canonical_side {
        CanonicalSide::Owner => &owner,
        CanonicalSide::Joiner => &joiner,
    };
    let (status, sealed_after) = seal_daemon
        .post(&format!("/groups/{home_id}/state/seal"), json!({}))
        .await?;
    ensure!(status == StatusCode::OK && sealed_after["ok"] == true);
    diagnostic.phase("final_stop")?;
    joiner.stop().await?;
    owner.stop().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires reviewed isolated-runtime admission"]
async fn home_onboarding_single_announce_restart() -> Result<()> {
    let diagnostic = TestDiagnostic::new()?;
    let guard = DiagnosticGuard(diagnostic.clone());
    let result = run_home_onboarding_scenario(diagnostic.clone()).await;
    diagnostic.finish(result.is_ok())?;
    drop(guard);
    result
}

#[test]
fn partial_or_wrong_port_advertisement_never_allows_http_probe() -> Result<()> {
    let expected: SocketAddr = "127.0.0.1:12600".parse()?;
    assert!(!advertised_matches("", expected));
    assert!(!advertised_matches("127.0.0.1:", expected));
    assert!(!advertised_matches("127.0.0.1:12601", expected));
    assert!(advertised_matches("127.0.0.1:12600\n", expected));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn readiness_rejects_success_at_or_after_absolute_deadline() {
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(30);
    assert!(readiness_success_allowed(started, deadline, true));
    assert!(!readiness_success_allowed(deadline, deadline, true));
    assert!(!readiness_success_allowed(
        deadline + Duration::from_nanos(1),
        deadline,
        true
    ));
    assert!(!readiness_success_allowed(started, deadline, false));
}

fn diagnostic_for_control(root: &TempDir, name: &str) -> Result<TestDiagnostic> {
    TestDiagnostic::new_bound(
        root.path().join(name),
        "34171638282:1".to_owned(),
        "a".repeat(40),
        "b".repeat(40),
    )
}

#[test]
fn diagnostic_refuses_preexisting_receipt() -> Result<()> {
    let root = TempDir::new()?;
    let path = root.path().join("diagnostic.json");
    std::fs::write(&path, "preexisting")?;
    assert!(TestDiagnostic::new_bound(
        path,
        "34171638282:1".to_owned(),
        "a".repeat(40),
        "b".repeat(40),
    )
    .is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn diagnostic_preserves_ordinary_error_and_early_child_reap() -> Result<()> {
    use std::os::unix::process::ExitStatusExt;

    let root = TempDir::new()?;
    let path = root.path().join("diagnostic.json");
    let diagnostic = diagnostic_for_control(&root, "diagnostic.json")?;
    let guard = DiagnosticGuard(diagnostic.clone());
    diagnostic.phase("owner_initial_start")?;
    diagnostic.child_started("owner_initial")?;
    diagnostic.child_reaped(
        "owner_initial",
        std::process::ExitStatus::from_raw(7 << 8),
        "none",
    )?;
    diagnostic.finish(false)?;
    drop(guard);
    let value: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    assert_eq!(value["result"], "failed");
    assert_eq!(value["failure_kind"], "stage_failed");
    assert_eq!(value["phase"], "owner_initial_start");
    assert_eq!(value["children"]["owner_initial"]["cleanup"], "reaped");
    assert_eq!(value["children"]["owner_initial"]["exit_code"], 7);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn diagnostic_records_spawned_child_when_readiness_fails() -> Result<()> {
    let root = TempDir::new()?;
    let path = root.path().join("diagnostic.json");
    let diagnostic = diagnostic_for_control(&root, "diagnostic.json")?;
    diagnostic.phase("owner_initial_start")?;
    let result = OwnedDaemon::start(
        Path::new("/usr/bin/false"),
        &root.path().join("unused.toml"),
        "127.0.0.1:9".parse()?,
        root.path().to_path_buf(),
        "owner_initial",
        diagnostic,
    )
    .await;
    assert!(result.is_err());
    let value: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    assert_eq!(value["children"]["owner_initial"]["started"], true);
    assert_eq!(value["children"]["owner_initial"]["cleanup"], "reaped");
    assert_eq!(value["children"]["owner_initial"]["exit_code"], 1);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn diagnostic_receipt_failure_reaps_already_spawned_child() -> Result<()> {
    let root = TempDir::new()?;
    let diagnostic = diagnostic_for_control(&root, "diagnostic.json")?;
    std::fs::write(root.path().join("diagnostic.json.next"), "occupied")?;
    let child = Command::new("/bin/sleep").arg("30").spawn()?;
    let pid = child.id().to_string();
    let daemon = OwnedDaemon {
        child: Some(child),
        label: "owner_initial",
        api: "127.0.0.1:9".parse()?,
        token: String::new(),
        data_dir: root.path().to_path_buf(),
        diagnostic,
    };
    assert!(daemon.record_started().is_err());
    drop(daemon);
    let alive = Command::new("/bin/kill").args(["-0", &pid]).status()?;
    assert!(!alive.success(), "receipt failure left owned child alive");
    Ok(())
}

#[test]
fn diagnostic_guard_preserves_unwind_phase() -> Result<()> {
    let root = TempDir::new()?;
    let path = root.path().join("diagnostic.json");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
        let diagnostic = diagnostic_for_control(&root, "diagnostic.json")?;
        let _guard = DiagnosticGuard(diagnostic.clone());
        diagnostic.phase("profile_identity")?;
        panic!("inert diagnostic unwind control")
    }));
    assert!(result.is_err());
    let value: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    assert_eq!(value["result"], "failed");
    assert_eq!(value["failure_kind"], "stage_failed");
    assert_eq!(value["phase"], "profile_identity");
    Ok(())
}
