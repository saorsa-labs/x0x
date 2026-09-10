#![allow(dead_code)]
//! Three-agent daemon orchestration for integration tests.
//!
//! Provides `AgentCluster` which manages 3 x0xd daemon processes
//! (alice, bob, charlie) with mutual discovery for multi-agent testing.

use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::time::Duration;
use tokio::sync::OnceCell;

#[path = "fixture_ownership.rs"]
mod fixture_ownership;
use fixture_ownership::{FixtureDirectory, OwnedChild, PortReservations};

/// A pair of daemon ports whose listeners remain held until the corresponding
/// child reaches the spawn boundary. Keeping the listeners alongside the
/// numbers prevents duplicate allocations within one fixture and protects
/// delayed rolling starts from unrelated claimants.
struct ReservedPorts {
    listeners: PortReservations,
    api_port: u16,
    bind_port: u16,
}

impl ReservedPorts {
    fn bind(name: &str) -> Self {
        let listeners = PortReservations::bind(0, 0)
            .unwrap_or_else(|error| panic!("Cannot reserve ports for {name}: {error}"));
        let (api_port, bind_port) = listeners
            .ports()
            .unwrap_or_else(|error| panic!("Cannot inspect reserved ports for {name}: {error}"));
        Self {
            listeners,
            api_port,
            bind_port,
        }
    }
}

/// A single x0xd daemon instance.
pub struct AgentInstance {
    process: OwnedChild,
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
    api_port: u16,
    bind_port: u16,
    directory: FixtureDirectory,
}

#[allow(dead_code)]
impl AgentInstance {
    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    /// PID of the daemon child process (black-hole / signal tests, #368).
    pub fn pid(&self) -> u32 {
        self.process.id()
    }

    /// Poll the daemon's exit status. Reaps the child when it has exited,
    /// so callers must NOT use `kill -0` style liveness checks on the PID
    /// (an unreaped child stays a zombie and `kill -0` keeps succeeding).
    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.process.try_wait()
    }

    pub fn directory_subscriptions_path(&self) -> PathBuf {
        self.data_dir.join("directory-subscriptions.json")
    }

    pub async fn restart(&mut self) {
        self.stop();
        self.start().await;
    }

    /// Kill the daemon process without restarting it. Pair with
    /// [`Self::start`] to create a downtime window during which other
    /// instances can mutate shared state (offline-mutation tests).
    pub fn stop(&mut self) {
        if let Err(error) = self.process.stop() {
            self.directory.preserve();
            panic!("Failed to stop owned x0xd {}: {error}", self.name);
        }
    }

    /// Start the daemon again after [`Self::stop`] and wait until healthy.
    ///
    /// Test-only: when `X0X_TEST_LOG_DIR` is set, the restarted daemon's
    /// stdout/stderr are appended to `{dir}/{name}.restart.{out,err}.log`
    /// (outside the per-node temp data_dir, so logs survive cleanup and are
    /// preserved on test failure). When unset, I/O is discarded as before.
    /// The daemon inherits `RUST_LOG` from this process — set it in the test
    /// environment to raise verbosity for post-restart diagnostics.
    pub async fn start(&mut self) {
        let reservations = self.prepare_start();
        let (stdout, stderr) = match test_log_stdio(&self.name, "restart") {
            Some(pair) => pair,
            None => (Stdio::null(), Stdio::null()),
        };
        let mut command = Command::new(&self.binary);
        command
            .arg("--config")
            .arg(&self.config_path)
            .arg("--name")
            .arg(&self.name)
            .stdout(stdout)
            .stderr(stderr);
        drop(reservations);
        self.process = OwnedChild::new(
            command
                .spawn()
                .unwrap_or_else(|e| panic!("Failed to restart x0xd {}: {e}", self.name)),
        );
        self.refresh_runtime_state().await;
    }
    /// Restart the daemon on a FORCED NEW QUIC (bind) port, keeping the same
    /// data_dir (hence the same `machine.key`/`agent.key` → same MachineId and
    /// QUIC peer_id), and with NO bootstrap peers configured.
    ///
    /// This is the named-node-restart primitive for the reconnect-policy
    /// regression: the restarted peer cannot startup-dial anyone (no
    /// bootstrap, `--no-hard-coded-bootstrap`), so the mesh can only reform
    /// via the SURVIVOR's proactive reconnect refreshing the new mDNS-announced
    /// endpoint. Returns the new QUIC bind port so the test can assert it
    /// differs from the pre-kill port (no fixed-port shortcut).
    pub async fn restart_on_new_quic_port_no_bootstrap(&mut self) -> u16 {
        self.stop();
        let new_bind = allocate_unused_udp_port();

        // Rewrite the config in place: drop every `bootstrap_peers` line (so
        // the restarted peer cannot initiate) and repoint `bind_address` at the
        // new port. `data_dir` is preserved verbatim → identity is preserved.
        let old_cfg = std::fs::read_to_string(&self.config_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", self.config_path.display()));
        let mut rebuilt = String::new();
        for line in old_cfg.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("bootstrap_peers") {
                continue;
            }
            if trimmed.starts_with("bind_address") {
                rebuilt.push_str(&format!("bind_address = \"0.0.0.0:{new_bind}\"\n"));
                continue;
            }
            rebuilt.push_str(line);
            rebuilt.push('\n');
        }
        std::fs::write(&self.config_path, &rebuilt)
            .unwrap_or_else(|e| panic!("rewrite {}: {e}", self.config_path.display()));

        self.bind_port = new_bind;
        let reservations = self.prepare_start();

        let (stdout, stderr) = match test_log_stdio(&self.name, "restart-newport") {
            Some(pair) => pair,
            None => (Stdio::null(), Stdio::null()),
        };
        let mut command = Command::new(&self.binary);
        command
            .arg("--config")
            .arg(&self.config_path)
            .arg("--name")
            .arg(&self.name)
            // No hard-coded internet bootstrap either: this peer must be
            // unreachable by its own dialing so reconnection is attributable
            // solely to the survivor's proactive path.
            .arg("--no-hard-coded-bootstrap")
            .stdout(stdout)
            .stderr(stderr);
        drop(reservations);
        self.process = OwnedChild::new(
            command
                .spawn()
                .unwrap_or_else(|e| panic!("Failed to restart x0xd {}: {e}", self.name)),
        );
        self.refresh_runtime_state().await;
        new_bind
    }

    fn prepare_start(&mut self) -> PortReservations {
        self.process
            .require_stopped()
            .unwrap_or_else(|e| panic!("Cannot start x0xd {}: {e}", self.name));
        self.directory.preserve();
        // A persistent token alone cannot distinguish a failed restart from a
        // foreign listener. Require an advertisement produced by this startup.
        self.directory
            .clear_api_advertisement()
            .unwrap_or_else(|e| panic!("clear owned api.port for {}: {e}", self.name));
        PortReservations::bind(self.api_port, self.bind_port)
            .unwrap_or_else(|e| panic!("Cannot admit x0xd {}: {e}", self.name))
    }

    fn require_running(&mut self) {
        self.process
            .require_running()
            .unwrap_or_else(|e| panic!("x0xd {} startup failed: {e}", self.name));
    }

    async fn refresh_runtime_state(&mut self) {
        let api_addr = self.api_addr.clone();
        // 90s, not 30s: debug-build daemons doing ML-DSA keygen plus
        // hard-coded internet bootstrap rounds come healthy anywhere from
        // ~15s to >30s depending on machine load — the old deadline was a
        // flakiness knife-edge for the first daemon of a run.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
        let client = reqwest::Client::new();
        let mut last_api_advertisement = None;
        loop {
            self.require_running();
            // Server startup writes api.port only after binding its listener
            // and loading causal state. This file is private and was cleared
            // before restart; never contact a health endpoint without it.
            if self
                .directory
                .advertises_api(&api_addr, &mut last_api_advertisement)
                .unwrap_or_else(|e| panic!("read owned api.port for {}: {e}", self.name))
            {
                if let Ok(resp) = client.get(format!("http://{api_addr}/health")).send().await {
                    self.require_running();
                    if resp.status().is_success() {
                        break;
                    }
                }
            }
            if tokio::time::Instant::now() > deadline {
                panic!(
                    "x0xd {} did not become healthy within 90s; last owned api.port: {:?}",
                    self.name, last_api_advertisement
                );
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let token_file = self.data_dir.join("api-token");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            self.require_running();
            if let Ok(token) = std::fs::read_to_string(&token_file) {
                let token = token.trim().to_string();
                if !token.is_empty() {
                    self.require_running();
                    self.api_token = token;
                    self.directory.allow_cleanup();
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

    /// Exchange the durable API token for a short-lived browser session token
    /// (#127 / WS1.6). Session tokens are the only kind accepted via `?token=`
    /// query strings on WS/SSE endpoints.
    pub async fn session_token(&self) -> String {
        let resp = reqwest::Client::new()
            .post(format!("http://{}/auth/session", self.api_addr))
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .expect("POST /auth/session failed");
        let json: serde_json::Value = resp.json().await.expect("/auth/session response json");
        json["session_token"]
            .as_str()
            .expect("session_token field")
            .to_string()
    }

    /// WebSocket URL with a short-lived session token in the query parameter
    /// (#127 / WS1.6). The durable token is no longer accepted in query strings.
    pub async fn ws_url(&self, path: &str) -> String {
        let session = self.session_token().await;
        format!("ws://{}{}?token={session}", self.api_addr, path)
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

    /// Wait until this daemon has *an* advert in its capability store.
    ///
    /// Since ADR 0030 slice 4 a bare `POST /direct/send` is a durable send, so it
    /// depends on the recipient's advert having converged. This shortens that
    /// window but does **not** close it: `capability_store_entries` is the only
    /// REST-visible signal, and it is a count — it cannot say whether the entry is
    /// the signed, machine-bound v2 binding the strict gate actually requires.
    ///
    /// Measured on this fixture: the first durable send to a peer takes ~17.5 s
    /// even after this wait returns (subsequent sends ~200-450 ms), because the
    /// send itself still performs the ADR 0030 §2 forced targeted refresh and
    /// waits for the gossip ACK. A caller whose HTTP timeout is below that will
    /// still fail. Closing the gap properly needs either a REST surface exposing
    /// per-peer advert state, or a product change to the cold-start path.
    ///
    /// # Panics
    ///
    /// Panics if no advert appears within `deadline`.
    pub async fn wait_for_durable_capability(&self, deadline: std::time::Duration) {
        let started = std::time::Instant::now();
        let mut polls = 0_usize;
        while started.elapsed() < deadline {
            polls += 1;
            let resp = self.get("/diagnostics/dm").await;
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if body["capability_store_entries"].as_u64().unwrap_or(0) > 0 {
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        panic!(
            "no peer capability advert converged within {deadline:?} ({polls} polls); \
             a durable /direct/send would 409"
        );
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
        if let Err(error) = self.process.stop() {
            self.directory.preserve();
            eprintln!("[cluster] could not stop owned x0xd {}: {error}", self.name);
        }
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
///
/// Hermetic: the pair gets its own gossip plane, so it neither sees nor is seen
/// by other x0x daemons on the machine. See
/// [`pair_with_extra_config_and_node_env`] for why that is not the default.
pub async fn pair() -> AgentPair {
    pair_with_extra_config("").await
}

/// Gossip plane shared by the [`solo`]/[`join_peer`] family for this test
/// process (#337).
///
/// `pair*` and the trio each mint an id inside a single constructor call, but
/// these are two independent entry points that must land on ONE plane:
/// [`join_peer`] bootstraps to a [`solo`] anchor and then asserts the two
/// peered, and it cannot read the anchor's plane. Nextest runs every test in its
/// own process, so a process-scoped id is per-test in practice — the daemons of
/// one test share a plane while other tests and ambient daemons stay out.
/// Mirrors `daemon.rs`'s `process_gossip_plane_id`.
fn solo_plane_id() -> &'static str {
    static PLANE_ID: LazyLock<String> =
        LazyLock::new(|| format!("x0x-test-{}", rand::random::<u32>()));
    PLANE_ID.as_str()
}

/// Start a single daemon with no bootstrap peers. Returns the instance
/// and its UDP bind port so a later daemon can bootstrap to it — the
/// staggered-start primitive for cold-late-join tests (issue #96), where
/// state must exist before the second daemon's process does.
pub async fn solo() -> (AgentInstance, u16) {
    let binary = find_x0xd_binary();
    let suffix = rand::random::<u16>();
    let ports = ReservedPorts::bind("solo");
    let bind = ports.bind_port;
    let instance = start_instance(
        &binary,
        &format!("solo-{suffix}"),
        ports,
        "",
        &with_private_plane(solo_plane_id(), ""),
    )
    .await;
    (instance, bind)
}

/// Start a daemon that bootstraps to an already-running instance's UDP
/// bind port (as returned by [`solo`]). Waits for the mesh to settle and
/// asserts the two nodes actually peered, mirroring [`pair`]'s guarantees.
pub async fn join_peer(anchor: &AgentInstance, anchor_bind: u16) -> AgentInstance {
    let binary = find_x0xd_binary();
    let suffix = rand::random::<u16>();
    let ports = ReservedPorts::bind("join_peer");
    let instance = start_instance(
        &binary,
        &format!("late-{suffix}"),
        ports,
        &format!("bootstrap_peers = [\"127.0.0.1:{anchor_bind}\"]"),
        &with_private_plane(solo_plane_id(), ""),
    )
    .await;
    tokio::time::sleep(MESH_SETTLE_TIME).await;
    assert_nodes_connected(&[anchor, &instance]).await;
    instance
}

pub async fn trio_with_extra_config(extra_config: &str) -> AgentCluster {
    create_cluster_with_extra_config(extra_config).await
}

/// Start a fresh pair with the same extra TOML appended to each daemon's
/// generated config. Useful for test-only timing overrides.
pub async fn pair_with_extra_config(extra_config: &str) -> AgentPair {
    pair_with_extra_config_and_node_env(extra_config, &[], &[]).await
}

/// Start a fresh pair with extra environment variables set on **bob only**.
///
/// Daemons otherwise inherit the test process environment, which is shared —
/// so a fault-injection hook set that way would fire on both nodes. Tests that
/// must break one side of a two-party exchange (e.g. #333: drop the joiner's
/// initial `MemberJoined` volley while the authority behaves normally) need
/// exactly one node configured, and bob is the harness's joiner.
pub async fn pair_with_bob_env(env: &[(&str, &str)]) -> AgentPair {
    pair_with_node_env(&[], env).await
}

/// Start a fresh pair with extra environment variables set on **alice only**.
///
/// The mirror of [`pair_with_bob_env`], for exchanges where alice is the
/// sender: she is the harness's group authority, so removals and deletes
/// originate with her (#333 slice C/D).
pub async fn pair_with_alice_env(env: &[(&str, &str)]) -> AgentPair {
    pair_with_node_env(env, &[]).await
}

/// Start a fresh pair with per-node environment variables. Either slice may be
/// empty; both nodes still inherit the test process environment on top.
pub async fn pair_with_node_env(alice_env: &[(&str, &str)], bob_env: &[(&str, &str)]) -> AgentPair {
    pair_with_extra_config_and_node_env("", alice_env, bob_env).await
}

/// Every `pair*` constructor funnels through here, so the hermetic-plane
/// guarantee below is stated once and cannot be forgotten by a new variant.
async fn pair_with_extra_config_and_node_env(
    extra_config: &str,
    alice_env: &[(&str, &str)],
    bob_env: &[(&str, &str)],
) -> AgentPair {
    let binary = find_x0xd_binary();
    let suffix = rand::random::<u16>();
    // Hermetic by default: give this pair its own gossip plane.
    //
    // `network_id` is unset in generated test configs, and
    // `DaemonConfig::resolved_network_id` (src/server/state.rs:568-574) maps
    // unset to the PROD plane. The plane id is also what namespaces ant-quic's
    // mDNS service (src/network.rs:1612-1618), so an unset value puts every
    // test pair on the prod plane's LAN discovery: it advertises to, browses,
    // and auto-connects to every other x0x daemon on the machine, including
    // unrelated app daemons. `--no-hard-coded-bootstrap` does not help — that
    // only stops this node dialling OUT, not others finding it.
    //
    // Measured on the two historically-flaky propagation tests (#337): 2/6
    // passing at 39-55s each without a private plane, 6/6 at 22-25s with one.
    // The pollution manifests as slow invite-join convergence, which is what
    // those tests wait on.
    let plane_id = format!("x0x-test-{}", rand::random::<u32>());
    let owned_extra = with_private_plane(&plane_id, extra_config);
    let extra_config = owned_extra.as_str();
    let alice_ports = ReservedPorts::bind("pair-alice");
    let alice_bind = alice_ports.bind_port;
    let bob_ports = ReservedPorts::bind("pair-bob");

    let alice = start_instance_with_env(
        &binary,
        &format!("pair-alice-{suffix}"),
        alice_ports,
        "",
        extra_config,
        alice_env,
    )
    .await;
    // Rolling start: use the same empirically-required delay as the trio so
    // bob has a stable alice to bootstrap against. The previous 5s was too
    // short and let propagation-dependent tests race mesh formation.
    tokio::time::sleep(ROLLING_START_DELAY).await;
    let bob = start_instance_with_env(
        &binary,
        &format!("pair-bob-{suffix}"),
        bob_ports,
        &format!("bootstrap_peers = [\"127.0.0.1:{alice_bind}\"]"),
        extra_config,
        bob_env,
    )
    .await;
    tokio::time::sleep(MESH_SETTLE_TIME).await;

    // Enforce peering before returning. Without this, propagation-dependent
    // assertions (member convergence, delete propagation) flake when alice and
    // bob have not yet connected — exactly the failure mode the trio path
    // already guards against via assert_mesh_connected.
    assert_nodes_connected(&[&alice, &bob]).await;

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

/// Prepend a private per-run gossip plane to `extra_config` unless the caller
/// already set one, so every daemon this harness starts is isolated from the
/// prod plane. See the rationale in `pair_with_extra_config_and_node_env`
/// (#337): an unset `network_id` resolves to PROD and namespaces mDNS, so test
/// daemons otherwise auto-connect to any live x0xd on the machine. The
/// suppression check mirrors `daemon.rs`'s `bootstrap_peers` handling — a
/// duplicate TOML key would be a parse error, and it lets a caller override the
/// plane deliberately.
/// The hermeticity line every harness-started daemon gets (#417).
///
/// An unset `mdns_enabled` resolves to `true` — the production default — which
/// leaves the fixture advertising and browsing on the LAN and AUTO-CONNECTING
/// to whatever it finds, including a live `x0xd` on the developer's own machine.
/// That is the #417 defect: test daemons join the prod mesh, inflate real
/// announce volume, and make co-located test runs fail non-deterministically.
/// `with_private_plane` above is NOT sufficient on its own — `network_id` only
/// *namespaces* mDNS, so a fixture that is handed the prod plane still finds
/// prod daemons.
///
/// Returns `""` when the caller already set the key, so a test that deliberately
/// exercises mDNS can opt back in; a duplicate TOML key is a parse error. This
/// is duplicated in `daemon.rs` because integration tests `#[path]`-include
/// each harness module on its own, with no shared crate root between them.
fn hermetic_mdns_line(extra_config: &str) -> &'static str {
    let caller_set_it = extra_config
        .lines()
        .any(|l| l.trim_start().starts_with("mdns_enabled"));
    if caller_set_it {
        ""
    } else {
        "mdns_enabled = false\n"
    }
}

fn with_private_plane(plane_id: &str, extra_config: &str) -> String {
    let has_network_id = extra_config
        .lines()
        .any(|l| l.trim_start().starts_with("network_id"));
    if has_network_id {
        extra_config.to_string()
    } else {
        format!("network_id = \"{plane_id}\"\n{extra_config}")
    }
}

async fn create_cluster_with_extra_config(extra_config: &str) -> AgentCluster {
    let binary = find_x0xd_binary();
    let suffix = rand::random::<u16>();
    // One plane id shared by all three nodes (they must discover each other),
    // unique to this cluster instance (no other run or ambient daemon joins).
    let plane_id = format!("x0x-test-{}", rand::random::<u32>());
    let owned_extra = with_private_plane(&plane_id, extra_config);
    let extra_config = owned_extra.as_str();
    let alice_ports = ReservedPorts::bind("cluster-alice");
    let alice_bind = alice_ports.bind_port;
    let bob_ports = ReservedPorts::bind("cluster-bob");
    let charlie_ports = ReservedPorts::bind("cluster-charlie");

    // Rolling start: each node needs time for its QUIC listener to bind and
    // mDNS/bootstrap to propagate before the next node comes up. Starting
    // all three simultaneously causes connection races and mesh instability.

    eprintln!("[cluster] starting alice...");
    let alice = start_instance(
        &binary,
        &format!("test-alice-{suffix}"),
        alice_ports,
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
        bob_ports,
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
        charlie_ports,
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
    assert_nodes_connected(&[alice, bob, charlie]).await;
    eprintln!("[cluster] mesh verified — all 3 nodes connected");
}

/// Poll `/peers` on each node until it reports at least one peer. Panics if any
/// node still has zero peers after 30s. A disconnected mesh produces flaky
/// propagation results, so we fail loudly here rather than let the test proceed
/// and time out on a downstream convergence assertion.
async fn assert_nodes_connected(nodes: &[&AgentInstance]) {
    for node in nodes {
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
}

fn find_x0xd_binary() -> PathBuf {
    // Runtime override — lets a test run pin the daemon build (e.g. to
    // prove a regression test fails against a pre-fix binary while the
    // test code itself compiles from the current tree).
    if let Ok(path) = std::env::var("X0XD_TEST_BINARY") {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
        panic!(
            "X0XD_TEST_BINARY set but does not exist: {}",
            path.display()
        );
    }
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

/// Test-only daemon log capture.
///
/// When `X0X_TEST_LOG_DIR` is set, returns stdout/stderr `Stdio` handles that
/// append to `{dir}/{name}.{suffix}.{out,err}.log`. That path lives outside the
/// per-node temp data_dir, so the logs survive data-dir cleanup and are
/// preserved on test failure. Returns `None` when the env var is unset so the
/// caller's default sink (per-node data-dir files, or `Stdio::null()`) is used
/// and other tests are unaffected.
///
/// The daemon inherits `RUST_LOG` from this process, so set `RUST_LOG` (e.g.
/// `x0x::crdt=debug,x0x::server=debug`) in the test environment to raise
/// verbosity; the directive is honoured by the daemon's `init_logging`.
fn test_log_stdio(name: &str, suffix: &str) -> Option<(Stdio, Stdio)> {
    let dir = std::env::var("X0X_TEST_LOG_DIR").ok()?;
    let dir = dir.trim();
    if dir.is_empty() {
        return None;
    }
    let _ = std::fs::create_dir_all(dir);
    let base = std::path::Path::new(dir).join(format!("{name}.{suffix}"));
    let open = || {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("{}.log", base.display()))
            .unwrap_or_else(|e| panic!("open test log {base:?}: {e}"))
    };
    // Two independent append handles to the same path; both file descriptions
    // share O_APPEND, so interleaved stdout/stderr writes stay ordered.
    Some((Stdio::from(open()), Stdio::from(open())))
}

async fn start_instance(
    binary: &PathBuf,
    name: &str,
    ports: ReservedPorts,
    bootstrap: &str,
    extra_config: &str,
) -> AgentInstance {
    start_instance_with_env(binary, name, ports, bootstrap, extra_config, &[]).await
}

/// As [`start_instance`], plus environment variables applied to this daemon
/// process only (on top of the inherited test environment).
async fn start_instance_with_env(
    binary: &PathBuf,
    name: &str,
    ports: ReservedPorts,
    bootstrap: &str,
    extra_config: &str,
    env: &[(&str, &str)],
) -> AgentInstance {
    let ReservedPorts {
        listeners: reservations,
        api_port,
        bind_port,
    } = ports;
    let directory = FixtureDirectory::new_in(&std::env::temp_dir())
        .unwrap_or_else(|e| panic!("create owned fixture directory for {name}: {e}"));
    let config_dir = directory.path().to_path_buf();

    let config_path = config_dir.join("config.toml");
    // NOTE: `[update] enabled = false` is MANDATORY in every test config —
    // test binaries otherwise SELF-REPLACE via gossip-delivered auto-update
    // (x0x#226 standing rule). It goes LAST so table sections opened by
    // `extra_config` cannot swallow the flat keys above it.
    // #417: hermetic by default. Sits with the other flat keys, ABOVE
    // `extra_config`, for the same reason `[update]` sits below it.
    let mdns_line = hermetic_mdns_line(extra_config);
    let config_content = format!(
        "api_address = \"127.0.0.1:{api_port}\"\n\
         bind_address = \"0.0.0.0:{bind_port}\"\n\
         data_dir = \"{}\"\n\
         identity_dir = \"{}/identity\"\n\
         log_level = \"warn\"\n\
         {mdns_line}\
         {bootstrap}\n\
         {extra_config}\n\
         [update]\n\
         enabled = false\n",
        config_dir.display(),
        config_dir.display()
    );
    std::fs::write(&config_path, &config_content).expect("write config");

    // Test-only capture (see `test_log_stdio`); fall back to per-node data-dir
    // logs so the default behaviour is unchanged.
    let (stdout, stderr) = match test_log_stdio(name, "start") {
        Some(pair) => pair,
        None => {
            let stdout_path = config_dir.join("daemon.stdout.log");
            let stderr_path = config_dir.join("daemon.stderr.log");
            let out = std::fs::File::create(&stdout_path)
                .unwrap_or_else(|e| panic!("Failed to create stdout log for {name}: {e}"));
            let err = std::fs::File::create(&stderr_path)
                .unwrap_or_else(|e| panic!("Failed to create stderr log for {name}: {e}"));
            (Stdio::from(out), Stdio::from(err))
        }
    };

    let mut command = Command::new(binary);
    command
        .arg("--config")
        .arg(&config_path)
        .arg("--name")
        .arg(name)
        .arg("--no-hard-coded-bootstrap")
        .stdout(stdout)
        .stderr(stderr);
    for (key, value) in env {
        command.env(key, value);
    }
    // Reservations cannot be handed to x0xd. Release only at the spawn boundary;
    // an intervening claimant must make this child fail, never be evicted.
    drop(reservations);
    let process = OwnedChild::new(
        command
            .spawn()
            .unwrap_or_else(|e| panic!("Failed to start x0xd {name}: {e}")),
    );

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
        api_port,
        bind_port,
        directory,
    };

    // Wait for health / token — if this panics, `instance` is dropped,
    // killing the process.
    instance.refresh_runtime_state().await;
    instance
}

#[cfg(test)]
mod reservation_tests {
    use super::{fixture_ownership::PortReservations, ReservedPorts};

    #[test]
    fn reserved_pair_ports_are_distinct_and_held() {
        let first = ReservedPorts::bind("pure-test-first");
        let second = ReservedPorts::bind("pure-test-second");

        assert_ne!(first.api_port, second.api_port);
        assert_ne!(first.bind_port, second.bind_port);
        assert!(PortReservations::bind(first.api_port, first.bind_port).is_err());
        assert!(PortReservations::bind(second.api_port, second.bind_port).is_err());
    }
}

#[cfg(test)]
mod hermeticity_tests {
    use super::hermetic_mdns_line;

    #[test]
    fn harness_daemons_disable_mdns_unless_the_test_opts_in() {
        // #417: a harness daemon must not be discoverable by — or able to
        // auto-connect to — a production daemon on the same machine. The key
        // is only absent-means-ON at the daemon, so if this line ever stops
        // being emitted, every test daemon silently rejoins the prod mesh.
        assert_eq!(hermetic_mdns_line(""), "mdns_enabled = false\n");
        assert_eq!(
            hermetic_mdns_line("bootstrap_peers = []\n"),
            "mdns_enabled = false\n"
        );

        // A test that is actually about mDNS must be able to turn it back on,
        // and emitting our line as well would be a duplicate-key parse error.
        assert_eq!(hermetic_mdns_line("mdns_enabled = true\n"), "");
        assert_eq!(hermetic_mdns_line("  mdns_enabled = false\n"), "");
    }
}
