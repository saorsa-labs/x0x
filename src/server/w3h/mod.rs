//! W3-H (#1164) simulation harness: real in-process daemons on the sim
//! fabric. Test builds only.
//!
//! Each node is the production daemon assembly
//! ([`super::serve_with_options`]) whose `NetworkNode` claimed a
//! [`crate::network::sim::SimFabric`] link instead of a QUIC socket. Cases
//! drive the public HTTP API through the daemon's own `Router`
//! (`tower::ServiceExt::oneshot`); no harness traffic uses a socket. Each
//! daemon still binds one idle loopback API listener that nothing uses.
//!
//! Time (plan §3b): a `spawn_blocking` clock gate inhibits tokio's
//! auto-advance whenever no named barrier is open, so virtual time moves
//! only inside [`Sim::within`] / [`Sim::until`] / [`Sim::api`], and every
//! advance is attributed to a named barrier in the trace. When the
//! entropy/wall-clock shim (`scripts/w3h/w3h_shim.c`) is preloaded, the
//! wall clock is a fixed base plus virtual time, updated every virtual
//! millisecond inside barriers, and all OS entropy is seeded.
//!
//! Determinism (plan §3a): [`Sim::finish`] renders the fabric's canonical
//! trace up to the `teardown begins` mark and prints
//! `W3H-TRACE case=… seed=… entropy=… digest=…`. The CI gate (ruling D196)
//! requires the same verdict with complete receipts in all 20 reruns and
//! reports the number of distinct digests per case without failing on it.
//! Teardown is recorded in a trace appendix that is not digested; a
//! teardown error still fails the run.
//! Every node's machine and agent keys are generated on the test thread
//! before any daemon starts ([`Sim::empty`]), so the entropy a daemon
//! draws can never shift a later node's identity.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod case_1143;
mod case_1207;
mod control;
mod home;
mod receipt;
mod restart;

// Kept apart from the list above so concurrent case branches never touch
// the same lines.
mod case_1256;
mod case_811;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use tower::ServiceExt;

use super::state::AppState;
use super::{serve_with_options, DaemonConfig, ServeOptions, ServerHandle};
use crate::identity::{AgentKeypair, MachineKeypair};
use crate::network::sim::{self, SimFabric};

/// Virtual-time budget for one API call (including any network round
/// trips it waits on).
const API_BUDGET: Duration = Duration::from_secs(60);
/// Upper bound for one run's raw payload dump.
const PAYLOAD_DUMP_CAP: usize = 32 * 1024 * 1024;
/// Separates the digested trace from the teardown appendix in a `.trace`
/// file (`scripts/ci/w3h-trace-check.py` compares only what precedes it).
const TRACE_APPENDIX: &str = "# --- appendix: teardown (not digested) ---";
/// Virtual-time budget for a daemon to start.
const START_BUDGET: Duration = Duration::from_secs(120);
/// Virtual time a stopped daemon's stray tasks get to release its state
/// before [`Sim::stop`] reports INFRA.
const DRAIN_BUDGET: Duration = Duration::from_secs(30);
/// Environment variable naming the agent-id order of a case's labels, from
/// lowest to highest (e.g. `A,X,O,J`): [`Sim::empty`] then assigns the
/// pre-generated keys sorted by agent id in that order. Set only by the
/// `w3h-permuted-*` nextest profiles (W3-H S3, ADR 0108 "repeat with
/// creator/admin identities permuted").
const IDENTITY_ORDER_ENV: &str = "W3H_IDENTITY_ORDER";
/// Real-time limit for an await made while the clock gate is closed. A
/// stall past it means the case needed time outside a named barrier.
const GATED_STALL_LIMIT: std::time::Duration = std::time::Duration::from_secs(20);

/// The preloaded `libw3h_shim.so`, if any.
#[derive(Clone, Copy)]
struct Shim {
    set_wall_offset_ns: unsafe extern "C" fn(u64),
    thread_stats: unsafe extern "C" fn(*mut libc::c_char, usize) -> libc::c_int,
}

/// Why the shim is not controlling this process (recorded in the trace).
const SHIM_NOT_LOADED: &str = "shim not preloaded";

impl Shim {
    /// The shim, if it is preloaded, active (it requires `W3H_SHIM_ACTIVE=1`
    /// and `W3H_ENTROPY_SEED`), and demonstrably intercepting both entropy
    /// paths: `rand::rngs::OsRng` (getrandom 0.2 → `syscall(SYS_getrandom)`)
    /// and libc `getrandom()` (std, getrandom 0.3/0.4). Otherwise the reason.
    #[cfg(target_os = "linux")]
    fn detect() -> std::result::Result<Self, String> {
        use rand::RngCore as _;
        // SAFETY: `dlsym` with RTLD_DEFAULT and NUL-terminated names has no
        // preconditions; null means "not found".
        let (set_wall, active, calls, stats) = unsafe {
            (
                libc::dlsym(libc::RTLD_DEFAULT, c"w3h_shim_set_wall_offset_ns".as_ptr()),
                libc::dlsym(libc::RTLD_DEFAULT, c"w3h_shim_active".as_ptr()),
                libc::dlsym(libc::RTLD_DEFAULT, c"w3h_shim_entropy_calls".as_ptr()),
                libc::dlsym(libc::RTLD_DEFAULT, c"w3h_shim_thread_stats".as_ptr()),
            )
        };
        if set_wall.is_null() || active.is_null() || calls.is_null() || stats.is_null() {
            return Err(SHIM_NOT_LOADED.to_string());
        }
        // SAFETY: these are the shim's exported functions with exactly these
        // C ABI signatures (`scripts/w3h/w3h_shim.c`).
        let (set_wall_offset_ns, active, calls) = unsafe {
            (
                std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn(u64)>(set_wall),
                std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn() -> libc::c_int>(
                    active,
                ),
                std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn() -> libc::c_ulong>(
                    calls,
                ),
            )
        };
        // SAFETY: plain reads of the shim's atomics.
        if unsafe { active() } != 1 {
            return Err("shim preloaded but inactive (W3H_SHIM_ACTIVE / W3H_ENTROPY_SEED)".into());
        }
        // SAFETY: as above.
        let before = unsafe { calls() };
        let _ = rand::rngs::OsRng.next_u64();
        let mut probe = [0u8; 8];
        // SAFETY: the buffer is valid for its length.
        let got = unsafe { libc::getrandom(probe.as_mut_ptr().cast(), probe.len(), 0) };
        // SAFETY: as above.
        let after = unsafe { calls() };
        if got != 8 || after < before.saturating_add(2) {
            return Err(format!(
                "shim active but an entropy path bypassed it (calls {before} -> {after})"
            ));
        }
        // SAFETY: the shim's `int w3h_shim_thread_stats(char *, size_t)`.
        let thread_stats = unsafe {
            std::mem::transmute::<
                *mut libc::c_void,
                unsafe extern "C" fn(*mut libc::c_char, usize) -> libc::c_int,
            >(stats)
        };
        Ok(Self {
            set_wall_offset_ns,
            thread_stats,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn detect() -> std::result::Result<Self, String> {
        Err(SHIM_NOT_LOADED.to_string())
    }

    /// Per-thread entropy draws (`name#ordinal=draws` lines). Diagnostics
    /// only; never part of the canonical trace.
    fn thread_stats(self) -> String {
        let mut buffer = vec![0u8; 64 * 1024];
        // SAFETY: the buffer is valid and writable for its length; the shim
        // NUL-terminates within `cap`.
        let threads = unsafe { (self.thread_stats)(buffer.as_mut_ptr().cast(), buffer.len()) };
        let end = buffer
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(buffer.len());
        format!(
            "{threads} threads\n{}",
            String::from_utf8_lossy(&buffer[..end])
        )
    }

    fn set_wall(self, offset: Duration) {
        let nanos = u64::try_from(offset.as_nanos()).unwrap_or(u64::MAX);
        // SAFETY: the shim's setter only stores atomics.
        unsafe { (self.set_wall_offset_ns)(nanos) }
    }
}

/// Holding one blocking task inhibits paused tokio's auto-advance
/// (tokio `runtime/blocking/schedule.rs`); releasing it allows it again.
struct ClockGate {
    release: std::sync::mpsc::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl ClockGate {
    fn close() -> Self {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let task = tokio::task::spawn_blocking(move || {
            let _ = wait.recv();
        });
        Self { release, task }
    }

    async fn open(self) {
        let _ = self.release.send(());
        let _ = self.task.await;
    }
}

/// How [`Sim::stop`] takes a daemon down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RestartMode {
    /// The daemon stays on the fabric while it shuts down, so its farewell
    /// traffic (disconnects, last publishes) is part of the trace.
    Graceful,
    /// The node is taken off the fabric first, so no frame leaves it after
    /// the crash mark. A model, not a real crash: in-process tasks still
    /// drain and file writes still complete (torn-write cases damage files
    /// between [`Sim::stop`] and [`Sim::start_again`] instead).
    Crash,
}

/// One simulated daemon.
pub(crate) struct SimNode {
    label: String,
    /// The node's address slot (`198.18.0.<index + 1>`), kept across restarts.
    index: usize,
    handle: Option<ServerHandle>,
    router: Option<axum::Router>,
    state: Weak<AppState>,
    /// The daemon's agent. It owns handles the next incarnation needs
    /// released (the history database connection, among others), and it
    /// can outlive the daemon state, so [`Sim::stop`] checks it too.
    agent: Weak<crate::Agent>,
    /// The daemon's history store, when history is on.
    history: Option<HistoryRelease>,
    token: String,
    peer: ant_quic::PeerId,
    agent_hex: String,
}

/// A daemon's history store as the drain sees it. The store is the one
/// owner of the SQLite connection that holds the database's EXCLUSIVE lock
/// from open to close; every holder (the agent's handle, the writer thread,
/// the reaper) shares one `Arc<Store>`. Its strong count reaches zero
/// before its destructor runs, possibly on another thread, so the drain
/// waits for the store's close watch, which fires only once the connection
/// has closed; the count is kept for the message.
#[derive(Clone)]
struct HistoryRelease {
    store: Weak<crate::history::store::Store>,
    closed: Arc<crate::history::store::close_watch::CloseWatch>,
}

impl HistoryRelease {
    fn of(store: &Arc<crate::history::store::Store>) -> Self {
        Self {
            store: Arc::downgrade(store),
            closed: store.close_watch(),
        }
    }
}

/// What a stopped node's next incarnation needs released before it starts
/// on the same dirs, checked by [`Sim::stop`]'s drain: the old daemon
/// state, agent and history store (no strong references left), and the
/// data-dir and identity-dir instance locks (#601, #645).
///
/// The history database is checked in memory, never through SQLite: its
/// EXCLUSIVE lock lives exactly as long as the store's connection, so a
/// closed connection ([`HistoryRelease`]) is a released lock. Opening the file,
/// even read-only, could change what the restart sees (SQLite deletes the
/// WAL of a zero-page database before any lock check). The instance locks
/// are observed without creating or writing anything
/// ([`instance_lock_held`]).
struct Release {
    state: Weak<AppState>,
    agent: Weak<crate::Agent>,
    /// The history database's path (for the message) and its store, when
    /// history is on.
    history_db: std::path::PathBuf,
    history: Option<HistoryRelease>,
    data_dir: std::path::PathBuf,
    identity_dir: Option<std::path::PathBuf>,
}

impl Release {
    /// Everything still held; empty once all of it is released. The lock
    /// files are probed only after every object is gone: an object still
    /// alive is the cause, and its locks would only repeat it. A probe that
    /// fails is reported, never read as released.
    fn held(&self) -> Vec<String> {
        let mut held = Vec::new();
        if self.state.strong_count() > 0 {
            held.push(format!(
                "daemon state by {} references",
                self.state.strong_count()
            ));
        }
        if self.agent.strong_count() > 0 {
            held.push(format!("agent by {} references", self.agent.strong_count()));
        }
        if let Some(history) = self
            .history
            .as_ref()
            .filter(|history| !history.closed.closed())
        {
            held.push(format!(
                "history db {} (its connection, with the EXCLUSIVE lock, has not closed; \
                 store held by {} references)",
                self.history_db.display(),
                history.store.strong_count()
            ));
        }
        if !held.is_empty() {
            return held;
        }
        let locks = std::iter::once(("data-dir", &self.data_dir))
            .chain(self.identity_dir.iter().map(|dir| ("identity-dir", dir)));
        for (what, dir) in locks {
            let path = dir.join(super::instance_lock::INSTANCE_LOCK_FILE);
            match instance_lock_held(&path) {
                Ok(false) => {}
                Ok(true) => held.push(format!("{what} instance lock {} (locked)", path.display())),
                Err(error) => held.push(format!(
                    "{what} instance lock {} (probe failed: {error})",
                    path.display()
                )),
            }
        }
        held
    }
}

/// Whether the instance lock file at `path` is locked, observed without
/// changing it. A missing file is not held (and is not created). Otherwise
/// the existing file is opened read-only (never created or truncated) and
/// the production lock primitive ([`crate::file_lock::try_lock_exclusive`],
/// a non-blocking `flock`, per open file description, so a holder in this
/// process is seen) is tried; a lock it gets is released when the file
/// closes, with the file's bytes and times untouched.
#[cfg(unix)]
fn instance_lock_held(path: &std::path::Path) -> std::io::Result<bool> {
    let file = match std::fs::OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(!crate::file_lock::try_lock_exclusive(&file)?)
}

/// Windows' instance lock is a share-mode open, which an observer cannot
/// test without holding the file itself; W3-H daemon cases run on Linux.
#[cfg(not(unix))]
fn instance_lock_held(_path: &std::path::Path) -> std::io::Result<bool> {
    Ok(false)
}

/// Identity material written into a node's identity directory before its
/// daemon starts (a fixture preparing signed capabilities, ADR 0108
/// Validation; never discovered certificate bytes).
/// Each field is the on-disk encoding (`crate::storage::serialize_*`, or
/// `AgentCertificate::to_storage_bytes()` — e.g. `POST /owner/agents/issue`
/// `certificate.storage_b64`).
#[derive(Default)]
pub(crate) struct Provision {
    pub(crate) machine_key: Option<Vec<u8>>,
    pub(crate) agent_key: Option<Vec<u8>>,
    pub(crate) user_key: Option<Vec<u8>>,
    pub(crate) agent_cert: Option<Vec<u8>>,
}

/// One WARN-or-worse log event from any in-process daemon, with the
/// virtual time it was emitted at.
#[derive(Clone, Debug)]
pub(crate) struct CapturedLog {
    pub(crate) at: Duration,
    pub(crate) text: String,
}

struct LogCapture {
    fabric: Arc<SimFabric>,
    logs: Arc<Mutex<Vec<CapturedLog>>>,
}

struct LogText<'a>(&'a mut String);

impl tracing::field::Visit for LogText<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        let _ = write!(self.0, "{}={:?} ", field.name(), value);
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LogCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut text = format!(
            "{} {}: ",
            event.metadata().level(),
            event.metadata().target()
        );
        event.record(&mut LogText(&mut text));
        self.logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(CapturedLog {
                at: self.fabric.now(),
                text,
            });
    }
}

/// A running scenario.
pub(crate) struct Sim {
    case: String,
    seed: u64,
    plane: String,
    fabric: Arc<SimFabric>,
    nodes: BTreeMap<String, SimNode>,
    gate: Mutex<Option<ClockGate>>,
    shim: Option<Shim>,
    logs: Arc<Mutex<Vec<CapturedLog>>>,
    /// Keys generated before any daemon started, not yet used by a node.
    keys: BTreeMap<String, (MachineKeypair, AgentKeypair)>,
    root: tempfile::TempDir,
    // Last: the capture stays installed until every daemon has stopped.
    _log_guard: tracing::subscriber::DefaultGuard,
}

fn sim_addr(index: usize) -> Result<SocketAddr> {
    let octet = u8::try_from(index + 1).context("too many simulated nodes")?;
    // 198.18.0.0/15 is reserved for benchmarking; it never routes.
    Ok(SocketAddr::from(([198, 18, 0, octet], 5483)))
}

/// Wait for `fut` while the clock gate is closed. Virtual time cannot
/// move, so a future that needs time stalls; a real-time watchdog turns
/// that into an INFRA error instead of a hang.
async fn gated<F: std::future::Future>(what: &str, fut: F) -> Result<F::Output> {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        std::thread::sleep(GATED_STALL_LIMIT);
        let _ = tx.send(());
    });
    tokio::select! {
        biased;
        out = fut => Ok(out),
        _ = rx => bail!("INFRA: '{what}' needed virtual time outside a named barrier"),
    }
}

/// A barrier's virtual budget ran out. Distinct from every other barrier
/// error (an INFRA stall, a failed read), so a wait whose expected outcome
/// is "never happened" accepts only this error ([`expired`]).
#[derive(Debug)]
pub(crate) struct BudgetExceeded {
    barrier: String,
    budget: Duration,
}

impl std::fmt::Display for BudgetExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "barrier '{}' exceeded its {:?} virtual budget",
            self.barrier, self.budget
        )
    }
}

impl std::error::Error for BudgetExceeded {}

/// Whether a barrier ended because its budget ran out.
pub(crate) fn expired(error: &anyhow::Error) -> bool {
    error.downcast_ref::<BudgetExceeded>().is_some()
}

/// The reads made inside one [`Sim::until`] predicate. A wait whose
/// expected outcome is "not yet" is only evidence when every read it made
/// completed and succeeded: a failed read (a broken endpoint) or a read cut
/// off by the budget (a hang) is INFRA, not "not admitted".
#[derive(Debug, Default)]
pub(crate) struct Observations {
    started: usize,
    completed: usize,
    failures: Vec<String>,
}

impl Observations {
    /// Await one read; `None` when it failed (recorded).
    pub(crate) async fn observe<T>(
        &mut self,
        read: impl std::future::Future<Output = Result<T>>,
    ) -> Option<T> {
        self.started += 1;
        let outcome = read.await;
        self.completed += 1;
        match outcome {
            Ok(value) => Some(value),
            Err(error) => {
                self.failures.push(format!("{error:#}"));
                None
            }
        }
    }

    /// Whether a read failed (the predicate should stop waiting).
    pub(crate) fn failed(&self) -> bool {
        !self.failures.is_empty()
    }

    /// INFRA unless at least one read completed, none failed and none was
    /// still running when the wait ended.
    pub(crate) fn verify(&self, what: &str) -> Result<()> {
        if let Some(first) = self.failures.first() {
            bail!(
                "INFRA: {what}: {} of {} reads failed; first: {first}",
                self.failures.len(),
                self.started
            );
        }
        ensure!(
            self.started == self.completed,
            "INFRA: {what}: a read was still running when the wait ended \
             ({} started, {} completed)",
            self.started,
            self.completed
        );
        ensure!(self.completed > 0, "INFRA: {what}: no read completed");
        Ok(())
    }
}

/// The permuted agent-id order of `labels` requested through
/// [`IDENTITY_ORDER_ENV`], if any. It must name exactly `labels`.
fn identity_order(labels: &[&str]) -> Result<Option<Vec<String>>> {
    let Ok(raw) = std::env::var(IDENTITY_ORDER_ENV) else {
        return Ok(None);
    };
    let order: Vec<String> = raw
        .split(',')
        .map(|label| label.trim().to_string())
        .collect();
    let mut wanted: Vec<&str> = order.iter().map(String::as_str).collect();
    let mut have = labels.to_vec();
    wanted.sort_unstable();
    have.sort_unstable();
    ensure!(
        wanted == have,
        "INFRA: {IDENTITY_ORDER_ENV}={raw} does not name exactly this case's nodes {labels:?}"
    );
    Ok(Some(order))
}

/// Whether this run of `case` writes a payload dump: the first run that
/// finishes (it records its digest in `<case>.first-digest`) and the first
/// run whose digest differs from it (`<case>.divergent-digest`). Later runs
/// write none, so a stress run keeps at most two dumps per case.
fn dump_this_run(dir: &std::path::Path, case: &str, digest: &str) -> bool {
    use std::io::Write as _;
    let claim = |name: String| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(name))
            .and_then(|mut file| file.write_all(digest.as_bytes()))
            .is_ok()
    };
    if claim(format!("{case}.first-digest")) {
        return true;
    }
    let first =
        std::fs::read_to_string(dir.join(format!("{case}.first-digest"))).unwrap_or_default();
    first.trim() != digest && claim(format!("{case}.divergent-digest"))
}

impl Sim {
    /// Start one daemon per label, in order, on a fresh fabric seeded by
    /// `seed`. Node 0 is every other node's bootstrap peer.
    pub(crate) async fn start(case: &str, seed: u64, labels: &[&str]) -> Result<Self> {
        let mut sim = Self::empty(case, seed, labels)?;
        for label in labels {
            sim.start_node_with(label, Provision::default()).await?;
        }
        Ok(sim)
    }

    /// A fabric, clock gate and WARN-log capture with no daemons yet.
    /// `labels` names every node the case will start: their machine and
    /// agent keys are generated here, on the test thread, before any daemon
    /// runs. Daemons draw entropy on the test thread too (one current-thread
    /// runtime), so a key generated after a daemon starts would depend on
    /// how many draws that daemon's tasks happened to make first.
    pub(crate) fn empty(case: &str, seed: u64, labels: &[&str]) -> Result<Self> {
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::Layer as _;
        let fabric = SimFabric::new(seed);
        let plane = format!("w3h-{seed:x}");
        sim::register(&plane, &fabric);
        let (shim, entropy) = match Shim::detect() {
            Ok(shim) => {
                shim.set_wall(Duration::ZERO);
                (Some(shim), "controlled".to_string())
            }
            Err(reason) => (None, format!("uncontrolled ({reason})")),
        };
        let mut keys = BTreeMap::new();
        let mut generated = Vec::with_capacity(labels.len());
        for _ in labels {
            generated.push((MachineKeypair::generate()?, AgentKeypair::generate()?));
        }
        let order = identity_order(labels)?;
        let assigned: Vec<&str> = match &order {
            Some(order) => {
                // Lowest agent id first; `order` names who plays each rank.
                generated.sort_by_key(|pair| pair.1.agent_id().0);
                order.iter().map(String::as_str).collect()
            }
            None => labels.to_vec(),
        };
        for (label, pair) in assigned.into_iter().zip(generated) {
            if keys.insert(label.to_string(), pair).is_some() {
                bail!("node label {label} declared twice");
            }
        }
        // Every case records the actual agent-id order of its labels, so a
        // permuted run that did not take effect is visible in its trace.
        let mut ranked: Vec<(&String, [u8; 32])> = keys
            .iter()
            .map(|(label, (_, agent))| (label, agent.agent_id().0))
            .collect();
        ranked.sort_by_key(|entry| entry.1);
        let ranked: Vec<&str> = ranked.iter().map(|(label, _)| label.as_str()).collect();
        if let Some(order) = &order {
            ensure!(
                ranked == order.iter().map(String::as_str).collect::<Vec<_>>(),
                "INFRA: identity order {order:?} did not take effect (got {ranked:?})"
            );
        }
        let ranked = ranked.join("<");
        let logs = Arc::new(Mutex::new(Vec::new()));
        // Thread-local: the scenario runs on one current-thread runtime, so
        // every daemon task emits on this thread.
        let log_guard = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(
                LogCapture {
                    fabric: Arc::clone(&fabric),
                    logs: Arc::clone(&logs),
                }
                .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
            ),
        );
        let sim = Self {
            case: case.to_string(),
            seed,
            plane,
            fabric,
            nodes: BTreeMap::new(),
            gate: Mutex::new(Some(ClockGate::close())),
            shim,
            logs,
            keys,
            root: tempfile::tempdir()?,
            _log_guard: log_guard,
        };
        sim.fabric.mark(format!("case {case} entropy={entropy}"));
        sim.fabric.mark(format!(
            "identity order {ranked} (by agent id{})",
            if order.is_some() { ", permuted" } else { "" }
        ));
        Ok(sim)
    }

    /// WARN-or-worse logs captured so far whose text contains every needle.
    pub(crate) fn logs_containing(&self, needles: &[&str]) -> Vec<CapturedLog> {
        self.logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|log| needles.iter().all(|needle| log.text.contains(needle)))
            .cloned()
            .collect()
    }

    /// The pre-generated machine and agent keys of `label` (see
    /// [`Self::empty`]). Each label's keys can be taken once.
    pub(crate) fn take_keys(&mut self, label: &str) -> Result<(MachineKeypair, AgentKeypair)> {
        self.keys.remove(label).ok_or_else(|| {
            anyhow!(
                "no pre-generated keys for {label}: declare every node label to \
                 Sim::empty / Sim::start, and start each node once"
            )
        })
    }

    fn daemon_config(&self, label: &str, index: usize) -> Result<DaemonConfig> {
        let dir = self.root.path().join(label);
        let mut config = DaemonConfig {
            api_address: SocketAddr::from(([127, 0, 0, 1], 0)),
            bind_address: sim_addr(index)?,
            data_dir: dir.join("data"),
            identity_dir: Some(dir.join("identity")),
            network_id: Some(self.plane.clone()),
            bootstrap_peers: Some(if index == 0 {
                Vec::new()
            } else {
                vec![sim_addr(0)?]
            }),
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..DaemonConfig::default()
        };
        config.api_watchdog.enabled = false;
        Ok(config)
    }

    /// Write `provision` into the node's identity directory, then start its
    /// daemon. A provision without machine and agent keys gets the label's
    /// pre-generated ones. The first node started is every later node's
    /// bootstrap peer.
    pub(crate) async fn start_node_with(
        &mut self,
        label: &str,
        mut provision: Provision,
    ) -> Result<()> {
        if provision.machine_key.is_none() || provision.agent_key.is_none() {
            let (machine, agent) = self.take_keys(label)?;
            if provision.machine_key.is_none() {
                provision.machine_key = Some(crate::storage::serialize_machine_keypair(&machine)?);
            }
            if provision.agent_key.is_none() {
                provision.agent_key = Some(crate::storage::serialize_agent_keypair(&agent)?);
            }
        }
        let index = self.nodes.len();
        let config = self.daemon_config(label, index)?;
        let identity = config
            .identity_dir
            .clone()
            .context("sim nodes always have an identity dir")?;
        tokio::fs::create_dir_all(&identity).await?;
        for (file, bytes) in [
            ("machine.key", provision.machine_key),
            ("agent.key", provision.agent_key),
            ("user.key", provision.user_key),
            ("agent.cert", provision.agent_cert),
        ] {
            if let Some(bytes) = bytes {
                crate::storage::write_private_bytes(&identity.join(file), bytes).await?;
            }
        }
        let node = self.serve_node(label, index, config).await?;
        // Identities are part of the canonical trace: if key generation ever
        // diverges, the gate's first differing line says so.
        self.fabric.mark(format!(
            "identity {label} agent={} machine={}",
            node.agent_hex,
            hex::encode(node.peer.0)
        ));
        self.nodes.insert(label.to_string(), node);
        Ok(())
    }

    /// Serve `label`'s daemon from `config` inside a `start` barrier.
    async fn serve_node(&self, label: &str, index: usize, config: DaemonConfig) -> Result<SimNode> {
        let options = ServeOptions {
            skip_update_check: true,
            cli_no_port_mapping: true,
            cli_disable_peer_cache: true,
            self_update_enabled: false,
            ..ServeOptions::default()
        };
        let handle = self
            .within(
                &format!("start {label}"),
                START_BUDGET,
                serve_with_options(config, options),
            )
            .await??;
        let state = handle
            .test_state
            .upgrade()
            .ok_or_else(|| anyhow!("daemon {label} state dropped during start"))?;
        let peer = state
            .agent
            .network()
            .ok_or_else(|| anyhow!("daemon {label} has no network"))?
            .peer_id();
        self.fabric.label(&peer, label);
        Ok(SimNode {
            label: label.to_string(),
            index,
            router: Some(handle.test_router.clone()),
            state: Arc::downgrade(&state),
            agent: Arc::downgrade(&state.agent),
            history: state
                .agent
                .history()
                .map(|history| HistoryRelease::of(history.store())),
            token: state.api_token.clone(),
            peer,
            agent_hex: hex::encode(state.agent.agent_id().as_bytes()),
            handle: Some(handle),
        })
    }

    /// Stop `label`'s daemon. A [`RestartMode::Crash`] takes the node off
    /// the fabric first; a [`RestartMode::Graceful`] stop leaves it online
    /// while it shuts down. The daemon drains inside a `stop` barrier, then
    /// everything its next incarnation needs must be released ([`Release`];
    /// a `drain` barrier lets virtual time pass so stray tasks can finish).
    /// Anything still held is INFRA: a stopped daemon's objects could still
    /// act on its data and identity dirs while the next incarnation uses
    /// them, and a held lock fails the restart itself.
    ///
    /// Returns the trace position just after the `fault stop` mark. For a
    /// crash, the node leaves the fabric at that position: the mark and
    /// `set_online(false)` run on the test thread with no await between
    /// them, so no daemon task can write in between.
    pub(crate) async fn stop(&mut self, label: &str, mode: RestartMode) -> Result<usize> {
        let mode_name = match mode {
            RestartMode::Graceful => "graceful",
            RestartMode::Crash => "crash",
        };
        let index = self.node(label)?.index;
        let config = self.daemon_config(label, index)?;
        let (handle, peer, release) = {
            let node = self
                .nodes
                .get_mut(label)
                .ok_or_else(|| anyhow!("no simulated node {label}"))?;
            let handle = node
                .handle
                .take()
                .ok_or_else(|| anyhow!("{label} is already stopped"))?;
            node.router = None;
            let release = Release {
                state: node.state.clone(),
                agent: node.agent.clone(),
                // As the daemon resolves it (server/mod.rs, ADR-0023).
                history_db: config
                    .history
                    .db_path
                    .clone()
                    .unwrap_or_else(|| config.data_dir.join("history.db")),
                history: node.history.clone(),
                data_dir: config.data_dir.clone(),
                identity_dir: config.identity_dir.clone(),
            };
            (handle, node.peer, release)
        };
        let stop_mark = self.fabric.cut(format!("fault stop {label} {mode_name}"));
        if mode == RestartMode::Crash {
            self.fabric.set_online(&peer, false);
        }
        self.within(
            &format!("stop {label}"),
            START_BUDGET,
            handle.shutdown_and_wait(),
        )
        .await?
        .with_context(|| format!("INFRA: {label} shutdown"))?;
        let released = self
            .until(&format!("drain {label}"), DRAIN_BUDGET, async |_: &Sim| {
                release.held().is_empty()
            })
            .await;
        if let Err(error) = released {
            if expired(&error) {
                bail!(
                    "INFRA: {label}'s stopped daemon is still held after its stop: {}; a \
                     stopped daemon could still act on its data and identity dirs",
                    release.held().join("; ")
                );
            }
            return Err(error);
        }
        self.fabric.mark(format!("stopped {label}"));
        Ok(stop_mark)
    }

    /// Start a stopped daemon again on the same data and identity dirs and
    /// the same address. Its machine key persists, so its peer id must be
    /// unchanged; the fabric attaches it as the next incarnation.
    pub(crate) async fn start_again(&mut self, label: &str) -> Result<()> {
        let (index, peer, agent_hex) = {
            let node = self.node(label)?;
            ensure!(node.handle.is_none(), "{label} is still running");
            (node.index, node.peer, node.agent_hex.clone())
        };
        let config = self.daemon_config(label, index)?;
        let node = self.serve_node(label, index, config).await?;
        ensure!(
            node.peer == peer && node.agent_hex == agent_hex,
            "INFRA: {label} restarted with a different identity"
        );
        let incarnation = self
            .fabric
            .incarnation_of(&peer)
            .context("restarted node is not on the fabric")?;
        self.fabric
            .mark(format!("restarted {label} inc={incarnation}"));
        self.nodes.insert(label.to_string(), node);
        Ok(())
    }

    /// [`Self::stop`] then [`Self::start_again`].
    pub(crate) async fn restart(&mut self, label: &str, mode: RestartMode) -> Result<()> {
        self.stop(label, mode).await?;
        self.start_again(label).await
    }

    /// A node's data dir, for fixture file damage while it is stopped.
    pub(crate) fn data_dir(&self, label: &str) -> Result<std::path::PathBuf> {
        ensure!(
            self.node(label)?.handle.is_none(),
            "{label} is running; stop it before touching its files"
        );
        Ok(self.root.path().join(label).join("data"))
    }

    /// The node's address slot (its sim address is `sim_addr(index)`).
    pub(crate) fn node_index(&self, label: &str) -> Result<usize> {
        Ok(self.node(label)?.index)
    }

    /// The node's transport peer id.
    pub(crate) fn peer(&self, label: &str) -> Result<ant_quic::PeerId> {
        Ok(self.node(label)?.peer)
    }

    fn node(&self, label: &str) -> Result<&SimNode> {
        self.nodes
            .get(label)
            .ok_or_else(|| anyhow!("no simulated node {label}"))
    }

    /// The node's agent id, hex.
    pub(crate) fn agent_hex(&self, label: &str) -> Result<String> {
        Ok(self.node(label)?.agent_hex.clone())
    }

    /// A label's agent and machine ids: from its pre-generated keys before
    /// its daemon starts ([`Self::empty`]), so a case can install fault
    /// rules about a node before it sends anything; from the node after.
    pub(crate) fn ids(
        &self,
        label: &str,
    ) -> Result<(crate::identity::AgentId, crate::identity::MachineId)> {
        if let Some((machine, agent)) = self.keys.get(label) {
            return Ok((agent.agent_id(), machine.machine_id()));
        }
        let node = self.node(label)?;
        let agent = <[u8; 32]>::try_from(hex::decode(&node.agent_hex)?.as_slice())
            .map_err(|_| anyhow!("{label}: malformed agent id"))?;
        Ok((
            crate::identity::AgentId(agent),
            crate::identity::MachineId(node.peer.0),
        ))
    }

    /// Read-only access to a running daemon's state.
    pub(crate) fn state(&self, label: &str) -> Result<Arc<AppState>> {
        self.node(label)?
            .state
            .upgrade()
            .ok_or_else(|| anyhow!("daemon {label} is not running"))
    }

    /// The fabric (faults, writes, trace).
    pub(crate) fn fabric(&self) -> &Arc<SimFabric> {
        &self.fabric
    }

    /// Run `fut` inside a named barrier: the clock gate opens, virtual time
    /// may auto-advance up to `budget`, then the gate closes again. The
    /// barrier, its virtual duration and outcome are recorded in the trace.
    pub(crate) async fn within<F: std::future::Future>(
        &self,
        name: &str,
        budget: Duration,
        fut: F,
    ) -> Result<F::Output> {
        let gate = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or_else(|| anyhow!("nested barrier '{name}'"))?;
        let started = self.fabric.now();
        self.fabric.mark(format!("barrier '{name}' open"));
        gate.open().await;
        let ticker = self.shim.map(|shim| {
            let fabric = Arc::clone(&self.fabric);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_millis(1));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tick.tick().await;
                    shim.set_wall(fabric.now());
                }
            })
        });
        let outcome = tokio::time::timeout(budget, fut).await;
        if let Some(ticker) = ticker {
            ticker.abort();
        }
        *self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ClockGate::close());
        if let Some(shim) = self.shim {
            shim.set_wall(self.fabric.now());
        }
        let elapsed = self.fabric.now().saturating_sub(started);
        self.fabric.mark(format!(
            "barrier '{name}' close {} after {}us",
            if outcome.is_ok() { "done" } else { "timeout" },
            elapsed.as_micros()
        ));
        outcome.map_err(|_| {
            anyhow::Error::new(BudgetExceeded {
                barrier: name.to_string(),
                budget,
            })
        })
    }

    /// A named barrier that polls `done` every 100 virtual ms until it
    /// holds or `budget` elapses.
    pub(crate) async fn until(
        &self,
        name: &str,
        budget: Duration,
        mut done: impl AsyncFnMut(&Sim) -> bool,
    ) -> Result<()> {
        self.within(name, budget, async {
            loop {
                if done(self).await {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
    }

    /// One public-API request through the node's router, inside its own
    /// named barrier. Returns the status and the JSON body (`Null` if the
    /// body is not JSON).
    pub(crate) async fn api(
        &self,
        label: &str,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<(StatusCode, serde_json::Value)> {
        let name = format!("api {label} {method} {path}");
        let result = self
            .within(&name, API_BUDGET, self.request(label, method, path, body))
            .await??;
        self.fabric.mark(format!("{name} -> {}", result.0));
        Ok(result)
    }

    /// The same request without a barrier, for use inside [`Self::until`]
    /// predicates (which already run inside one).
    pub(crate) async fn request(
        &self,
        label: &str,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<(StatusCode, serde_json::Value)> {
        let node = self.node(label)?;
        let router = node
            .router
            .clone()
            .ok_or_else(|| anyhow!("daemon {label} is not running"))?;
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {}", node.token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.map_or_else(Body::empty, |json| Body::from(json.to_string())))?;
        let response = router.oneshot(request).await?;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024).await?;
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        Ok((status, json))
    }

    /// Take a node off the fabric (it keeps running, unreachable).
    pub(crate) fn set_online(&self, label: &str, online: bool) -> Result<()> {
        let peer = self.node(label)?.peer;
        self.fabric.mark(format!(
            "fault {label} {}",
            if online { "online" } else { "offline" }
        ));
        self.fabric.set_online(&peer, online);
        Ok(())
    }

    /// Wait for a future at the current, frozen virtual instant.
    pub(crate) async fn at_instant<F: std::future::Future>(
        &self,
        what: &str,
        fut: F,
    ) -> Result<F::Output> {
        gated(what, fut).await
    }

    /// Finish the case whatever its outcome, so a failed control still
    /// writes its trace: the failure is marked first, then [`Self::finish`]
    /// runs, and the scenario error (if any) wins over a teardown error.
    pub(crate) async fn conclude(self, outcome: Result<()>) -> Result<()> {
        if let Err(error) = &outcome {
            self.fabric.mark(format!("scenario failed: {error:#}"));
        }
        let finished = self.finish().await;
        outcome?;
        finished.map(|_| ())
    }

    /// Every node's KV stores, for the non-digested `<case>-<pid>.kv`
    /// diagnostics file: version, local sequence counter, served digest,
    /// and every live entry with its OR-set tag and timestamps. Read-only.
    async fn kv_probe(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        for (label, node) in &self.nodes {
            let Some(state) = node.state.upgrade() else {
                continue;
            };
            let stores = state.kv_stores.read().await;
            let mut ids: Vec<&String> = stores.keys().collect();
            ids.sort();
            for id in ids {
                let Some(handle) = stores.get(id) else {
                    continue;
                };
                let store = handle.sync.read().await;
                let _ = writeln!(
                    out,
                    "{label} store={id} version={} seq_counter={} served_digest={}",
                    store.current_version(),
                    store.seq_counter_value(),
                    hex::encode(store.served_digest())
                );
                match store.full_delta() {
                    Ok(delta) => {
                        let mut added: Vec<_> = delta.added.iter().collect();
                        added.sort_by(|a, b| a.0.cmp(b.0));
                        for (key, (entry, (peer, seq))) in added {
                            let mut metadata: Vec<_> = entry.metadata.iter().collect();
                            metadata.sort();
                            let _ = writeln!(
                                out,
                                "  {key} tag={}:{seq} created_at={} updated_at={} \
                                 content_hash={} metadata={metadata:?}",
                                hex::encode(peer.as_bytes()),
                                entry.created_at,
                                entry.updated_at,
                                hex::encode(entry.content_hash),
                            );
                        }
                        let _ = writeln!(
                            out,
                            "  delta version={} removed={} updated={}",
                            delta.version,
                            delta.removed.len(),
                            delta.updated.len()
                        );
                    }
                    Err(error) => {
                        let _ = writeln!(out, "  full_delta error: {error}");
                    }
                }
            }
        }
        out
    }

    /// Mark `teardown begins`, stop every daemon (in label order, each
    /// inside a named barrier) and verify the teardown. Then print the
    /// digest of the canonical trace up to that mark and, when
    /// `W3H_TRACE_DIR` is set, write `<case>-<pid>.trace` (the digested
    /// trace, then the teardown as a non-digested appendix),
    /// `<case>-<pid>.entropy` (per-thread draw counts) and `<case>-<pid>.kv`
    /// (every node's KV stores, read before teardown). Teardown runs on
    /// real OS threads as well as the runtime, so its timing is not part of
    /// the digest; a barrier timeout or a supervisor error still fails the
    /// run (after the trace is written).
    pub(crate) async fn finish(mut self) -> Result<String> {
        // Diagnostics only (never digested): read while the daemons run.
        let kv = match gated("kv probe", self.kv_probe()).await {
            Ok(kv) => kv,
            Err(error) => format!("kv probe failed: {error:#}\n"),
        };
        let cut = self.fabric.cut("teardown begins");
        let handles: Vec<(String, ServerHandle)> = self
            .nodes
            .values_mut()
            .filter_map(|node| {
                node.router = None;
                node.handle
                    .take()
                    .map(|handle| (node.label.clone(), handle))
            })
            .collect();
        let mut teardown_errors = Vec::new();
        for (label, handle) in handles {
            match self
                .within(
                    &format!("stop {label}"),
                    START_BUDGET,
                    handle.shutdown_and_wait(),
                )
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => teardown_errors.push(format!("{label}: shutdown: {error:#}")),
                Err(error) => teardown_errors.push(format!("{label}: {error:#}")),
            }
        }
        for node in self.nodes.values() {
            // A leaked holder of the daemon state is reported, not failed:
            // the supervisor already drained (`shutdown_and_wait` returned
            // Ok) and the count of stray holders is scheduling-dependent.
            if node.state.upgrade().is_some() {
                eprintln!(
                    "W3H-WARN {}: daemon state outlived its shutdown",
                    node.label
                );
            }
        }
        self.fabric.mark(if teardown_errors.is_empty() {
            "teardown verified".to_string()
        } else {
            format!("teardown failed: {}", teardown_errors.join("; "))
        });
        let trace = self.fabric.canonical_trace_until(cut);
        let digest = blake3::hash(trace.as_bytes()).to_hex().to_string();
        let entropy = if self.shim.is_some() {
            "controlled"
        } else {
            "uncontrolled"
        };
        eprintln!(
            "W3H-TRACE case={} seed={:#x} entropy={entropy} digest={digest}",
            self.case, self.seed
        );
        let stats = self.shim.map(Shim::thread_stats);
        if let Ok(dir) = std::env::var("W3H_TRACE_DIR") {
            let dir = std::path::PathBuf::from(dir);
            if std::fs::create_dir_all(&dir).is_ok() {
                let stem = format!("{}-{}", self.case, std::process::id());
                let file = format!(
                    "{trace}{TRACE_APPENDIX}\n{}",
                    self.fabric.trace_appendix(cut)
                );
                let _ = std::fs::write(dir.join(format!("{stem}.trace")), file);
                if let Some(stats) = &stats {
                    let _ = std::fs::write(dir.join(format!("{stem}.entropy")), stats);
                }
                if !kv.is_empty() {
                    let _ = std::fs::write(dir.join(format!("{stem}.kv")), &kv);
                }
                // Raw payloads (test identities only) are written only when
                // the CI gate job asks for them (nextest `w3h-gate` profile),
                // and only for the first run of a case and the first run
                // whose digest differs from it.
                if std::env::var("W3H_DUMP_PAYLOADS").as_deref() == Ok("1")
                    && dump_this_run(&dir, &self.case, &digest)
                {
                    let _ = std::fs::write(
                        dir.join(format!("{stem}.payloads")),
                        self.fabric.payload_dump(PAYLOAD_DUMP_CAP),
                    );
                }
            }
        }
        for line in stats.iter().flat_map(|stats| stats.lines()) {
            eprintln!("W3H-ENTROPY {} {line}", self.case);
        }
        if !teardown_errors.is_empty() {
            bail!("teardown failed: {}", teardown_errors.join("; "));
        }
        Ok(digest)
    }

    /// Live fabric links of a node.
    pub(crate) async fn connected_peer_count(&self, label: &str) -> usize {
        match self.state(label) {
            Ok(state) => match state.agent.network() {
                Some(network) => network.connected_peers().await.len(),
                None => 0,
            },
            Err(_) => 0,
        }
    }
}

/// Seconds, for readable budgets.
pub(crate) const fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}
