//! #287 diagnostic only. No original WS selector calls this controller.
use super::daemon::{diagnostic_file, DaemonFixture, DiagnosticCleanup};
use base64::Engine;
use futures::{FutureExt, SinkExt, StreamExt};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;

fn diagnostic_hash(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
const WORK_MS: u64 = 540_000;
const CLEANUP_MS: u64 = 570_000;
const WAVE_MS: u64 = 20_000;
const MAX_WAVES: u64 = 4096;
const BODY_LIMIT: usize = 65536;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Arm {
    Stalled,
    Draining,
}
impl Arm {
    fn index(self) -> usize {
        if self == Self::Stalled {
            0
        } else {
            1
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
enum Class {
    Fail,
    Inconclusive,
    Incomplete,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
struct Problem {
    class: Class,
    code: &'static str,
}
type Result<T> = std::result::Result<T, Problem>;
fn fail(code: &'static str) -> Problem {
    Problem {
        class: Class::Fail,
        code,
    }
}
fn incomplete(code: &'static str) -> Problem {
    Problem {
        class: Class::Incomplete,
        code,
    }
}
fn premise(code: &'static str) -> Problem {
    Problem {
        class: Class::Inconclusive,
        code,
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
enum RequestState {
    Pending,
    Entered,
    Headers,
    Complete,
    RequestError,
    BodyError,
    Timeout,
    Non200,
    BodyLimit,
    Cancelled,
}
#[derive(Clone, Debug, Serialize)]
struct RequestOutcome {
    ordinal: usize,
    state: RequestState,
    status: Option<u16>,
    entered_ms: Option<u64>,
    headers_ms: Option<u64>,
    eof_ms: Option<u64>,
    body_bytes: usize,
    body_sha256: Option<String>,
}
impl RequestOutcome {
    fn pending(ordinal: usize) -> Self {
        Self {
            ordinal,
            state: RequestState::Pending,
            status: None,
            entered_ms: None,
            headers_ms: None,
            eof_ms: None,
            body_bytes: 0,
            body_sha256: None,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
struct Wave {
    arm: Arm,
    ordinal: u64,
    requests: Vec<RequestOutcome>,
    capture_complete: bool,
}
impl Wave {
    fn outcome(&self) -> Result<()> {
        // An observed oracle failure dominates a missing sibling record.
        if self.requests.iter().any(|r| {
            r.status.is_some_and(|status| status != 200)
                || matches!(
                    r.state,
                    RequestState::RequestError
                        | RequestState::BodyError
                        | RequestState::Timeout
                        | RequestState::Non200
                )
        }) {
            return Err(fail("HTTP_PUBLISH_ORACLE"));
        }
        if !self.capture_complete
            || self.requests.len() != 64
            || self.requests.iter().enumerate().any(|(i, r)| {
                r.ordinal != i
                    || r.state != RequestState::Complete
                    || r.status != Some(200)
                    || r.entered_ms.is_none()
                    || r.headers_ms.is_none()
                    || r.eof_ms.is_none()
                    || r.body_sha256.is_none()
            })
        {
            return Err(incomplete("HTTP_WAVE_INCOMPLETE"));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
struct Counters {
    dropped: u64,
    closes: u64,
    capture_complete: bool,
}
impl Counters {
    fn captured(&self) -> Result<()> {
        if self.capture_complete {
            Ok(())
        } else {
            Err(incomplete("COUNTER_CAPTURE_IO"))
        }
    }
}
#[derive(Default, Serialize)]
struct Transcript {
    phases: Vec<&'static str>,
    problems: Vec<Problem>,
    waves: [u64; 2],
    cleanup_complete: bool,
}
impl Transcript {
    fn problem(&mut self, p: Problem) {
        self.problems.push(p);
    }
    fn status(&self) -> &'static str {
        if self.problems.iter().any(|p| p.class == Class::Fail) {
            "FAIL"
        } else if !self.cleanup_complete
            || self.problems.iter().any(|p| p.class == Class::Incomplete)
        {
            "INCOMPLETE"
        } else if !self.problems.is_empty() {
            "INCONCLUSIVE"
        } else {
            "LOCAL_ORACLES_PASS"
        }
    }
}

// The real and constructor-free implementations drive this same phase controller.
trait Harness {
    fn now_ms(&self) -> u64;
    fn checkpoint(&mut self, trace: &Transcript) -> Result<()>;
    async fn setup(&mut self, end_ms: u64) -> Result<()>;
    async fn counters(&mut self, arm: Arm, end_ms: u64) -> Result<Counters>;
    async fn wave(&mut self, arm: Arm, ordinal: u64, end_ms: u64) -> Result<Wave>;
    async fn survival(&mut self) -> Result<()>;
    async fn finish_stalled(&mut self, baseline: Counters, end_ms: u64) -> Result<()>;
    async fn finish_draining(
        &mut self,
        baseline: Counters,
        expected: u64,
        end_ms: u64,
    ) -> Result<()>;
    async fn cleanup(&mut self, end_ms: u64) -> Vec<Problem>;
}
fn replay_capacity(elapsed: u64) -> u64 {
    WORK_MS.saturating_sub(elapsed).saturating_sub(55_000) / WAVE_MS
}
async fn compare<H: Harness>(h: &mut H, trace: &mut Transcript) -> Result<()> {
    trace.phases.push("setup_entered");
    h.checkpoint(trace)?;
    h.setup(80_000).await?;
    trace.phases.push("setup_complete");
    h.checkpoint(trace)?;
    h.survival().await?;
    let base = h
        .counters(Arm::Stalled, h.now_ms().saturating_add(10_000).min(WORK_MS))
        .await?;
    base.captured()?;
    let fill_end = h
        .now_ms()
        .saturating_add(180_000)
        .min(WORK_MS.saturating_sub(70_000));
    let mut dropped = base.dropped;
    trace.phases.push("stalled_fill_entered");
    h.checkpoint(trace)?;
    while dropped <= base.dropped {
        if h.now_ms() >= fill_end {
            return Err(premise("SATURATION_NOT_ESTABLISHED"));
        }
        if trace.waves[0] >= MAX_WAVES {
            return Err(incomplete("WAVE_CAPTURE_LIMIT"));
        }
        let n = trace.waves[0];
        let wave = h
            .wave(
                Arm::Stalled,
                n,
                fill_end.min(h.now_ms().saturating_add(WAVE_MS)),
            )
            .await?;
        if !wave.capture_complete {
            trace.problem(incomplete("WAVE_CAPTURE_IO"));
        }
        wave.outcome()?;
        trace.waves[0] += 1;
        h.checkpoint(trace)?;
        h.survival().await?;
        let c = h.counters(Arm::Stalled, fill_end).await?;
        if c.dropped < base.dropped || c.closes < base.closes {
            return Err(incomplete("COUNTER_DECREASE"));
        }
        c.captured()?;
        dropped = c.dropped;
    }
    trace.phases.push("stalled_saturation_established");
    h.checkpoint(trace)?;
    if h.now_ms().saturating_add(70_000) > WORK_MS {
        return Err(incomplete("STALLED_PHASE_BUDGET"));
    }
    h.finish_stalled(base, h.now_ms() + 70_000).await?;
    trace.phases.push("stalled_oracles_complete");
    h.checkpoint(trace)?;
    h.survival().await?;
    let drain_base = h
        .counters(
            Arm::Draining,
            h.now_ms().saturating_add(10_000).min(WORK_MS),
        )
        .await?;
    drain_base.captured()?;
    let n = trace.waves[0];
    if n == 0 || n > replay_capacity(h.now_ms()).min(MAX_WAVES) {
        return Err(premise("COMPARISON_BUDGET_UNAVAILABLE"));
    }
    trace.phases.push("matched_replay_admitted");
    h.checkpoint(trace)?;
    for ordinal in 0..n {
        let end = h
            .now_ms()
            .saturating_add(WAVE_MS)
            .min(WORK_MS.saturating_sub(55_000));
        let wave = h.wave(Arm::Draining, ordinal, end).await?;
        if !wave.capture_complete {
            trace.problem(incomplete("WAVE_CAPTURE_IO"));
        }
        wave.outcome()?;
        trace.waves[1] += 1;
        h.checkpoint(trace)?;
        h.survival().await?;
        let c = h.counters(Arm::Draining, end).await?;
        if c.dropped != drain_base.dropped || c.closes != drain_base.closes {
            return Err(fail("DRAINING_DROP_OR_CLOSE"));
        }
        c.captured()?;
    }
    if h.now_ms().saturating_add(55_000) > WORK_MS {
        return Err(incomplete("DRAINING_OBSERVATION_BUDGET"));
    }
    h.finish_draining(drain_base, n * 64, WORK_MS).await?;
    trace.phases.push("both_local_oracles_complete");
    h.checkpoint(trace)?;
    h.survival().await
}
async fn control<H: Harness>(h: &mut H) -> Transcript {
    let mut trace = Transcript::default();
    // Capture unexpected assertion failures separately from evidence cancellation.
    match std::panic::AssertUnwindSafe(compare(h, &mut trace))
        .catch_unwind()
        .await
    {
        Ok(Err(p)) => trace.problem(p),
        Err(_) => trace.problem(fail("ASSERTION_OR_PANIC")),
        Ok(Ok(())) => {}
    }
    if let Err(p) = h.checkpoint(&trace) {
        trace.problem(p);
    }
    let cleanup = h.cleanup(CLEANUP_MS).await;
    trace.cleanup_complete = !cleanup.iter().any(|p| p.class == Class::Incomplete);
    for problem in cleanup {
        trace.problem(problem);
    }
    if let Err(p) = h.checkpoint(&trace) {
        trace.problem(p);
    }
    trace
}

#[derive(Debug, PartialEq, Eq)]
enum WireObservation {
    Buffered,
    Close1013,
}
fn wire_observation(
    message: Option<std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>,
) -> Result<WireObservation> {
    match message {
        Some(Ok(Message::Close(frame)))
            if frame.as_ref().map(|f| u16::from(f.code)) == Some(1013) =>
        {
            Ok(WireObservation::Close1013)
        }
        Some(Ok(Message::Close(_))) => Err(fail("STALLED_WRONG_CLOSE")),
        Some(Ok(_)) => Ok(WireObservation::Buffered),
        Some(Err(_)) => Err(fail("STALLED_SOCKET_ERROR")),
        None => Err(fail("STALLED_EOF")),
    }
}

struct Capture {
    root: PathBuf,
    next: u64,
    nonce: String,
}
fn private_directory(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}
fn existing_directory(path: &Path) -> std::io::Result<()> {
    let info = std::fs::symlink_metadata(path)?;
    if info.file_type().is_symlink() || !info.is_dir() {
        return Err(std::io::Error::other(
            "capture path must be a real directory",
        ));
    }
    Ok(())
}
impl Capture {
    fn create() -> std::io::Result<Self> {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let canonical = manifest.canonicalize()?;
        if canonical != manifest {
            return Err(std::io::Error::other("noncanonical capture workspace"));
        }
        let target = manifest.join("target");
        if !target.exists() {
            private_directory(&target)?;
        }
        existing_directory(&target)?;
        let parent = target.join("issue287-captures");
        match private_directory(&parent) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => existing_directory(&parent)?,
            Err(e) => return Err(e),
        }
        let nonce = hex::encode(rand::random::<[u8; 16]>());
        let root = parent.join(&nonce);
        private_directory(&root)?;
        let mut capture = Self {
            root,
            next: 0,
            nonce,
        };
        let lock = manifest.join("Cargo.lock");
        std::io::copy(
            &mut std::fs::File::open(&lock)?,
            &mut diagnostic_file(&capture.root.join("Cargo.lock"))?,
        )?;
        let mut sources = serde_json::Map::new();
        for name in [
            "tests/ws_integration.rs",
            "tests/harness/src/daemon.rs",
            "tests/harness/src/ws_backpressure_diagnostic.rs",
        ] {
            sources.insert(
                name.into(),
                Value::String(diagnostic_hash(&manifest.join(name))?),
            );
        }
        capture.write("inputs", &json!({"selector":"ws_backpressure_matched_reader_acceptance", "test_binary_sha256":diagnostic_hash(&std::env::current_exe()?)?,
            "actual_lock_sha256":diagnostic_hash(&lock)?, "source_files":sources,
            "external_source_reuse_namespace_retention_readback":"UNVERIFIED"})).map_err(|_|std::io::Error::other("capture write"))?;
        Ok(capture)
    }
    fn bounds(&self) -> Result<()> {
        fn visit(p: &Path, total: &mut u64) -> std::io::Result<()> {
            for entry in std::fs::read_dir(p)? {
                let entry = entry?;
                let meta = std::fs::symlink_metadata(entry.path())?;
                if meta.file_type().is_symlink() {
                    return Err(std::io::Error::other("capture symlink"));
                }
                if meta.is_dir() {
                    visit(&entry.path(), total)?;
                } else if meta.is_file() {
                    *total = total.saturating_add(meta.len());
                    if meta.len() > 128 * 1024 * 1024 || *total > 1024 * 1024 * 1024 {
                        return Err(std::io::Error::other("capture bound"));
                    }
                } else {
                    return Err(std::io::Error::other("capture special file"));
                }
            }
            Ok(())
        }
        visit(&self.root, &mut 0).map_err(|_| incomplete("CAPTURE_BOUND_OR_IO"))
    }
    fn write<T: Serialize>(&mut self, kind: &str, data: &T) -> Result<()> {
        self.bounds()?;
        let path = self.root.join(format!("{:06}-{kind}.json", self.next));
        self.next += 1;
        let file = diagnostic_file(&path).map_err(|_| incomplete("CAPTURE_IO"))?;
        serde_json::to_writer(
            &file,
            &json!({"schema":"x0x.issue287-local/1","nonce":self.nonce,"kind":kind,"data":data}),
        )
        .map_err(|_| incomplete("CAPTURE_JSON"))?;
        file.sync_all().map_err(|_| incomplete("CAPTURE_IO"))?;
        self.bounds()
    }
}
#[derive(Default, Clone, Serialize)]
struct Reader {
    started: bool,
    frames: u64,
    last_frame_ms: Option<u64>,
    unexpected: u64,
    error: Option<&'static str>,
    stopped: bool,
}
impl Reader {
    fn record_frame(&mut self, elapsed_ms: u64) {
        self.frames = self.frames.saturating_add(1);
        self.last_frame_ms = Some(elapsed_ms);
    }
    fn by_deadline(&self, expected: u64, deadline_ms: u64) -> bool {
        self.frames == expected && self.last_frame_ms.is_some_and(|last| last <= deadline_ms)
    }
}
// Retain an established oracle failure even when its evidence write also fails.
fn retain_problem(result: &mut Result<()>, next: Result<()>) {
    if let Err(problem) = next {
        if result.is_ok()
            || (problem.class == Class::Fail
                && result.as_ref().is_err_and(|p| p.class != Class::Fail))
        {
            *result = Err(problem);
        }
    }
}
fn final_draining_outcome(
    health: Result<Value>,
    present: Result<bool>,
    counters: Result<Value>,
    reader: Result<Reader>,
    base: Counters,
    expected: u64,
    drain_end: u64,
) -> Result<()> {
    let mut result = health.map(|_| ());
    retain_problem(
        &mut result,
        present.and_then(|present| {
            if present {
                Ok(())
            } else {
                Err(fail("DRAINING_SESSION_REMOVED"))
            }
        }),
    );
    retain_problem(
        &mut result,
        counters.and_then(|c| {
            if c["ws_outbound_dropped"].as_u64() == Some(base.dropped)
                && c["ws_slow_consumer_closes"].as_u64() == Some(base.closes)
            {
                Ok(())
            } else {
                Err(fail("DRAINING_DROP_OR_CLOSE"))
            }
        }),
    );
    retain_problem(
        &mut result,
        reader.and_then(|r| {
            if let Some(code) = r.error {
                Err(fail(code))
            } else if !r.by_deadline(expected, drain_end) {
                Err(fail("DRAINING_FRAME_COUNT"))
            } else {
                Ok(())
            }
        }),
    );
    result
}
fn child_cleanup_problems(receipt: &DiagnosticCleanup) -> Vec<Problem> {
    let mut problems = Vec::new();
    if receipt.deliberate_termination == Some(false) {
        problems.push(fail("OWN_DAEMON_EXIT"));
    }
    if !receipt.reaped || receipt.exit.is_none() || receipt.deliberate_termination.is_none() {
        problems.push(incomplete("OWN_CHILD_REAP_UNPROVEN"));
    }
    if !receipt.capture_complete {
        problems.push(incomplete("CHILD_CLEANUP_CAPTURE_INCOMPLETE"));
    }
    if !receipt.identity_removed {
        problems.push(incomplete("CHILD_IDENTITY_CLEANUP_INCOMPLETE"));
    }
    problems.extend(receipt.errors.iter().map(|code| incomplete(code)));
    problems
}
struct Live {
    start: Instant,
    capture: Capture,
    daemons: [Option<DaemonFixture>; 2],
    clients: [Option<reqwest::Client>; 2],
    stalled: Option<Socket>,
    topics: [String; 2],
    sessions: [String; 2],
    payload: String,
    reader: Arc<Mutex<Reader>>,
    reader_task: Option<tokio::task::JoinHandle<()>>,
    cleanup_observations: Vec<DiagnosticCleanup>,
}
impl Live {
    fn new(capture: Capture, start: Instant) -> Self {
        Self {
            start,
            capture,
            daemons: [None, None],
            clients: [None, None],
            stalled: None,
            topics: [
                format!("ws287-stalled-{}", rand::random::<u64>()),
                format!("ws287-draining-{}", rand::random::<u64>()),
            ],
            sessions: [String::new(), String::new()],
            payload: base64::engine::general_purpose::STANDARD.encode([b'x'; 16 * 1024]),
            reader: Arc::new(Mutex::new(Reader::default())),
            reader_task: None,
            cleanup_observations: Vec::new(),
        }
    }
    fn at(&self, ms: u64) -> Instant {
        self.start + Duration::from_millis(ms.min(WORK_MS))
    }
    fn child(&self, arm: Arm) -> Result<&DaemonFixture> {
        self.daemons[arm.index()]
            .as_ref()
            .ok_or_else(|| incomplete("DAEMON_MISSING"))
    }
    fn client(&self, arm: Arm) -> Result<&reqwest::Client> {
        self.clients[arm.index()]
            .as_ref()
            .ok_or_else(|| incomplete("CLIENT_MISSING"))
    }
    async fn json_get(&self, arm: Arm, path: &str, end: u64) -> Result<Value> {
        let client = self.client(arm)?;
        let url = self.child(arm)?.url(path);
        tokio::time::timeout_at(self.at(end), async {
            let mut response = client
                .get(url)
                .send()
                .await
                .map_err(|_| fail("HTTP_PROBE_TRANSPORT"))?;
            if response.status() != 200 {
                return Err(fail("HTTP_PROBE_STATUS"));
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| fail("HTTP_PROBE_BODY"))?
            {
                if bytes.len() + chunk.len() > BODY_LIMIT {
                    return Err(incomplete("HTTP_PROBE_LIMIT"));
                }
                bytes.extend_from_slice(&chunk);
            }
            serde_json::from_slice(&bytes).map_err(|_| fail("HTTP_PROBE_JSON"))
        })
        .await
        .map_err(|_| incomplete("DIAGNOSTIC_DEADLINE"))?
    }
    async fn connect(&self, arm: Arm, end: u64) -> Result<(Socket, String)> {
        // Session tokens are never recorded or formatted into diagnostics.
        let d = self.child(arm)?;
        let client = self.client(arm)?;
        tokio::time::timeout_at(self.at(end), async {
            let response = client
                .post(d.url("/auth/session"))
                .send()
                .await
                .map_err(|_| premise("SETUP_SESSION"))?;
            if response.status() != 200 {
                return Err(premise("SETUP_SESSION"));
            }
            let bytes = response
                .bytes()
                .await
                .map_err(|_| premise("SETUP_SESSION"))?;
            if bytes.len() > BODY_LIMIT {
                return Err(incomplete("SETUP_BODY_LIMIT"));
            }
            let value: Value =
                serde_json::from_slice(&bytes).map_err(|_| premise("SETUP_SESSION"))?;
            let token = value["session_token"]
                .as_str()
                .ok_or_else(|| premise("SETUP_SESSION"))?;
            let url = format!("ws://{}/ws?token={token}", d.api_addr());
            let (mut ws, _) = tokio_tungstenite::connect_async(url)
                .await
                .map_err(|_| premise("SETUP_WEBSOCKET"))?;
            let first = ws
                .next()
                .await
                .ok_or_else(|| premise("SETUP_CONNECTED"))?
                .map_err(|_| premise("SETUP_CONNECTED"))?;
            let Message::Text(text) = first else {
                return Err(premise("SETUP_CONNECTED"));
            };
            let first: Value =
                serde_json::from_str(&text).map_err(|_| premise("SETUP_CONNECTED"))?;
            let session = first["session_id"]
                .as_str()
                .ok_or_else(|| premise("SETUP_CONNECTED"))?
                .to_owned();
            ws.send(Message::Text(
                json!({"type":"subscribe","topics":[self.topics[arm.index()]]}).to_string(),
            ))
            .await
            .map_err(|_| premise("SETUP_SUBSCRIBE"))?;
            loop {
                match ws.next().await {
                    Some(Ok(Message::Text(text))) => {
                        let v: Value =
                            serde_json::from_str(&text).map_err(|_| premise("SETUP_SUBSCRIBE"))?;
                        match v["type"].as_str() {
                            Some("subscribed") => break,
                            Some("pong") => {}
                            _ => return Err(premise("SETUP_SUBSCRIBE")),
                        }
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    _ => return Err(premise("SETUP_SUBSCRIBE")),
                }
            }
            Ok((ws, session))
        })
        .await
        .map_err(|_| premise("SETUP_DEADLINE"))?
    }
    fn reader_snapshot(&self) -> Result<Reader> {
        self.reader
            .lock()
            .map(|r| r.clone())
            .map_err(|_| incomplete("READER_POISON"))
    }
    async fn present(&self, arm: Arm, end: u64) -> Result<bool> {
        let v = self.json_get(arm, "/ws/sessions", end).await?;
        let rows = v["sessions"]
            .as_array()
            .ok_or_else(|| fail("SESSION_SCHEMA"))?;
        Ok(rows
            .iter()
            .any(|s| s["session_id"].as_str() == Some(self.sessions[arm.index()].as_str())))
    }
}

impl Harness for Live {
    fn now_ms(&self) -> u64 {
        self.start
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
    fn checkpoint(&mut self, trace: &Transcript) -> Result<()> {
        self.capture.write(
            "checkpoint",
            &json!({"elapsed_ms":self.now_ms(),"trace":trace,"local_status":trace.status(),
            "reader":self.reader_snapshot()?,"cleanup_observations":self.cleanup_observations,"external_custody_retention_readback":"UNVERIFIED"}),
        )
    }
    async fn setup(&mut self, end_ms: u64) -> Result<()> {
        for arm in [Arm::Stalled, Arm::Draining] {
            let dir = self.capture.root.join(if arm == Arm::Stalled {
                "stalled"
            } else {
                "draining"
            });
            private_directory(&dir).map_err(|_| incomplete("CAPTURE_DIRECTORY"))?;
            let plane = format!("ws287-{}-{}", self.capture.nonce, arm.index());
            self.daemons[arm.index()] = Some(
                DaemonFixture::spawn_diagnostic(&dir, &plane, diagnostic_hash)
                    .map_err(|_| premise("DAEMON_SPAWN"))?,
            );
        }
        let end = self.at(end_ms);
        let (left, right) = self.daemons.split_at_mut(1);
        let a = left[0]
            .as_mut()
            .ok_or_else(|| incomplete("DAEMON_MISSING"))?;
        let b = right[0]
            .as_mut()
            .ok_or_else(|| incomplete("DAEMON_MISSING"))?;
        let (a, b) = tokio::join!(a.diagnostic_ready(end), b.diagnostic_ready(end));
        a.map_err(premise)?;
        b.map_err(premise)?;
        for arm in [Arm::Stalled, Arm::Draining] {
            self.clients[arm.index()] =
                Some(self.child(arm)?.authed_client(Duration::from_secs(10)));
        }
        let (a, b) = tokio::join!(
            self.connect(Arm::Stalled, end_ms),
            self.connect(Arm::Draining, end_ms)
        );
        let (stalled, session) = a?;
        self.stalled = Some(stalled);
        self.sessions[0] = session;
        let (mut draining, session) = b?;
        self.sessions[1] = session;
        let state = self.reader.clone();
        let topic = self.topics[1].clone();
        let payload = self.payload.clone();
        let reader_start = self.start;
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        self.reader_task = Some(tokio::spawn(async move {
            if let Ok(mut r) = state.lock() {
                r.started = true;
            } else {
                return;
            }
            let _ = ready_tx.send(());
            loop {
                let message = draining.next().await;
                let mut r = match state.lock() {
                    Ok(r) => r,
                    Err(_) => return,
                };
                match message {
                    Some(Ok(Message::Text(text))) => match serde_json::from_str::<Value>(&text) {
                        Ok(v)
                            if v["type"].as_str() == Some("message")
                                && v["topic"].as_str() == Some(topic.as_str())
                                && v["payload"].as_str() == Some(payload.as_str()) =>
                        {
                            r.record_frame(reader_start.elapsed().as_millis() as u64);
                        }
                        Ok(v) if v["type"].as_str() == Some("pong") => {}
                        _ => {
                            r.unexpected = r.unexpected.saturating_add(1);
                            r.error = Some("DRAINING_UNEXPECTED_FRAME");
                        }
                    },
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) => {
                        r.error = Some("DRAINING_CLOSE");
                        r.stopped = true;
                        return;
                    }
                    Some(Err(_)) => {
                        r.error = Some("DRAINING_SOCKET_ERROR");
                        r.stopped = true;
                        return;
                    }
                    None => {
                        r.error = Some("DRAINING_EOF");
                        r.stopped = true;
                        return;
                    }
                    _ => {
                        r.unexpected = r.unexpected.saturating_add(1);
                        r.error = Some("DRAINING_UNEXPECTED_FRAME");
                    }
                }
            }
        }));
        tokio::time::timeout_at(end, ready_rx)
            .await
            .map_err(|_| premise("READER_START_DEADLINE"))?
            .map_err(|_| premise("READER_NOT_STARTED"))?;
        self.capture.write("workload",&json!({"payload_bytes":16384,"payload_base64_sha256":hex::encode(Sha256::digest(self.payload.as_bytes())),
            "concurrency":64,"request_timeout_ms":10000,"wave_algorithm":"all full bodies then counters","network_planes":"distinct per arm"}))
    }
    async fn counters(&mut self, arm: Arm, end_ms: u64) -> Result<Counters> {
        let v = self.json_get(arm, "/diagnostics/ws", end_ms).await?;
        let mut c = Counters {
            dropped: v["ws_outbound_dropped"]
                .as_u64()
                .ok_or_else(|| fail("COUNTER_SCHEMA"))?,
            closes: v["ws_slow_consumer_closes"]
                .as_u64()
                .ok_or_else(|| fail("COUNTER_SCHEMA"))?,
            capture_complete: true,
        };
        c.capture_complete = self
            .capture
            .write(
                "counters",
                &json!({"arm":arm,"elapsed_ms":self.now_ms(),"counters":c}),
            )
            .is_ok();
        Ok(c)
    }
    async fn wave(&mut self, arm: Arm, ordinal: u64, end_ms: u64) -> Result<Wave> {
        let client = self.client(arm)?.clone();
        let url = self.child(arm)?.url("/publish");
        let data = json!({"topic":self.topics[arm.index()],"payload":self.payload});
        let board = Arc::new(Mutex::new(
            (0..64).map(RequestOutcome::pending).collect::<Vec<_>>(),
        ));
        let mut pending = futures::stream::FuturesUnordered::new();
        for i in 0..64 {
            let (client, url, data, board, start) = (
                client.clone(),
                url.clone(),
                data.clone(),
                board.clone(),
                self.start,
            );
            pending.push(async move {
                let elapsed = || u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                let update = |f: fn(&mut RequestOutcome), state: RequestState| {
                    if let Ok(mut rows) = board.lock() {
                        rows[i].state = state;
                        f(&mut rows[i]);
                    }
                };
                if let Ok(mut rows) = board.lock() {
                    rows[i].state = RequestState::Entered;
                    rows[i].entered_ms = Some(elapsed());
                }
                let mut response = match client.post(url).json(&data).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        update(
                            |_| {},
                            if e.is_timeout() {
                                RequestState::Timeout
                            } else {
                                RequestState::RequestError
                            },
                        );
                        return;
                    }
                };
                let status = response.status().as_u16();
                if let Ok(mut rows) = board.lock() {
                    rows[i].state = RequestState::Headers;
                    rows[i].status = Some(status);
                    rows[i].headers_ms = Some(elapsed());
                }
                let mut hash = Sha256::new();
                let mut count = 0;
                loop {
                    match response.chunk().await {
                        Ok(Some(bytes)) => {
                            count += bytes.len();
                            if let Ok(mut rows) = board.lock() {
                                rows[i].body_bytes = count;
                            }
                            if count > BODY_LIMIT {
                                update(|_| {}, RequestState::BodyLimit);
                                return;
                            }
                            hash.update(&bytes);
                        }
                        Ok(None) => {
                            if let Ok(mut rows) = board.lock() {
                                rows[i].state = if status == 200 {
                                    RequestState::Complete
                                } else {
                                    RequestState::Non200
                                };
                                rows[i].eof_ms = Some(elapsed());
                                rows[i].body_sha256 = Some(hex::encode(hash.finalize()));
                            }
                            return;
                        }
                        Err(e) => {
                            update(
                                |_| {},
                                if e.is_timeout() {
                                    RequestState::Timeout
                                } else {
                                    RequestState::BodyError
                                },
                            );
                            return;
                        }
                    }
                }
            });
        }
        let end = self.at(end_ms);
        loop {
            match tokio::time::timeout_at(end, pending.next()).await {
                Ok(Some(())) => {}
                Ok(None) => break,
                Err(_) => break,
            }
        }
        drop(pending); // Mark each genuinely entered unfinished request; never call it completed.
        let mut rows = board
            .lock()
            .map_err(|_| incomplete("REQUEST_BOARD_POISON"))?
            .clone();
        for r in &mut rows {
            if matches!(
                r.state,
                RequestState::Pending | RequestState::Entered | RequestState::Headers
            ) {
                r.state = RequestState::Cancelled;
            }
        }
        let mut wave = Wave {
            arm,
            ordinal,
            requests: rows,
            capture_complete: true,
        };
        // All sibling outcomes are persisted before the controller asserts the oracle.
        if self.capture.write("wave", &wave).is_err() {
            wave.capture_complete = false;
        }
        Ok(wave)
    }
    async fn survival(&mut self) -> Result<()> {
        let mut observations = Vec::new();
        let mut result = Ok(());
        for d in self.daemons.iter_mut().flatten() {
            match d.diagnostic_child() {
                Ok(v) => {
                    if v["alive"] != true {
                        retain_problem(&mut result, Err(fail("OWN_DAEMON_EXIT")));
                    }
                    observations.push(v);
                }
                Err(_) => retain_problem(&mut result, Err(incomplete("CHILD_STATE_IO"))),
            }
        }
        retain_problem(
            &mut result,
            self.capture.write(
                "children",
                &json!({"elapsed_ms":self.now_ms(),"children":observations}),
            ),
        );
        if self
            .reader_task
            .as_ref()
            .is_none_or(|task| task.is_finished())
        {
            retain_problem(&mut result, Err(fail("DRAINING_READER_TASK_STOPPED")));
        }
        match self.reader_snapshot() {
            Ok(reader) => {
                if let Some(code) = reader.error {
                    retain_problem(&mut result, Err(fail(code)));
                }
                if !reader.started || reader.stopped {
                    retain_problem(&mut result, Err(fail("DRAINING_READER_NOT_LIVE")));
                }
            }
            Err(problem) => retain_problem(&mut result, Err(problem)),
        }
        result
    }
    async fn finish_stalled(&mut self, base: Counters, end_ms: u64) -> Result<()> {
        let close_end = self.now_ms().saturating_add(45_000).min(end_ms);
        loop {
            if self.now_ms() >= close_end {
                return Err(fail("STALLED_CLOSE_MISSING"));
            }
            let c = self.counters(Arm::Stalled, close_end).await?;
            if c.closes > base.closes {
                if c.closes != base.closes + 1 {
                    return Err(fail("STALLED_CLOSE_COUNT"));
                }
                c.captured()?;
                break;
            }
            if self.now_ms() >= close_end {
                return Err(fail("STALLED_CLOSE_MISSING"));
            }
            c.captured()?;
            tokio::time::sleep_until(
                self.at(close_end)
                    .min(Instant::now() + Duration::from_millis(100)),
            )
            .await;
        }
        let wire_end = self.now_ms().saturating_add(15_000).min(end_ms);
        let at = self.at(wire_end);
        let ws = self
            .stalled
            .as_mut()
            .ok_or_else(|| incomplete("STALLED_SOCKET_MISSING"))?;
        tokio::time::timeout_at(at, async {
            loop {
                if wire_observation(ws.next().await)? == WireObservation::Close1013 {
                    return Ok::<(), Problem>(());
                }
            }
        })
        .await
        .map_err(|_| fail("STALLED_WIRE_CLOSE_MISSING"))??;
        self.capture.write(
            "wire_close",
            &json!({"arm":Arm::Stalled,"close_code":1013,"elapsed_ms":self.now_ms()}),
        )?;
        let sessions_end = self.now_ms().saturating_add(10_000).min(end_ms);
        loop {
            if self.now_ms() >= sessions_end {
                return Err(fail("STALLED_SESSION_RETAINED"));
            }
            if !self.present(Arm::Stalled, sessions_end).await? {
                break;
            }
            if self.now_ms() >= sessions_end {
                return Err(fail("STALLED_SESSION_RETAINED"));
            }
            tokio::time::sleep_until(
                self.at(sessions_end)
                    .min(Instant::now() + Duration::from_millis(100)),
            )
            .await;
        }
        Ok(())
    }
    async fn finish_draining(&mut self, base: Counters, expected: u64, end_ms: u64) -> Result<()> {
        let began = self.now_ms();
        let drain_end = began + 15_000;
        let observe_end = began + 45_000;
        if observe_end + 10_000 > end_ms {
            return Err(incomplete("DRAINING_OBSERVATION_BUDGET"));
        }
        loop {
            self.survival().await?;
            let r = self.reader_snapshot()?;
            if r.frames > expected
                || (self.now_ms() >= drain_end && !r.by_deadline(expected, drain_end))
            {
                return Err(fail("DRAINING_FRAME_COUNT"));
            }
            if self.now_ms() >= observe_end {
                break;
            }
            let c = self
                .counters(Arm::Draining, observe_end.min(self.now_ms() + 10_000))
                .await?;
            if c.dropped != base.dropped || c.closes != base.closes {
                return Err(fail("DRAINING_DROP_OR_CLOSE"));
            }
            c.captured()?;
            if self.now_ms() >= observe_end {
                break;
            }
            tokio::time::sleep_until(
                self.at(observe_end)
                    .min(Instant::now() + Duration::from_millis(100)),
            )
            .await;
        }
        let (health, present, counters) = tokio::join!(
            self.json_get(Arm::Draining, "/health", end_ms),
            self.present(Arm::Draining, end_ms),
            self.json_get(Arm::Draining, "/diagnostics/ws", end_ms)
        );
        let capture = match &counters {
            Ok(value) => self.capture.write("draining_final_counters", value),
            Err(_) => Ok(()),
        };
        let mut result = final_draining_outcome(
            health,
            present,
            counters,
            self.reader_snapshot(),
            base,
            expected,
            drain_end,
        );
        retain_problem(&mut result, capture);
        result
    }

    async fn cleanup(&mut self, end_ms: u64) -> Vec<Problem> {
        let deadline = self.start + Duration::from_millis(end_ms);
        let mut problems = Vec::new();
        if let Some(task) = self.reader_task.take() {
            task.abort();
            match tokio::time::timeout_at(deadline, task).await {
                Ok(Err(error)) if error.is_cancelled() => {}
                Ok(Err(_)) => problems.push(fail("READER_TASK_PANIC")),
                Ok(Ok(())) => problems.push(fail("READER_TASK_STOPPED")),
                Err(_) => problems.push(incomplete("READER_TASK_UNREAPED")),
            }
        }
        // Each Child's reap is attempted; every observed failure and custody gap survives.
        for d in self.daemons.iter_mut().flatten() {
            let receipt = d.diagnostic_finish(deadline).await;
            problems.extend(child_cleanup_problems(&receipt));
            self.cleanup_observations.push(receipt);
        }
        if let Err(problem) = self.capture.bounds() {
            problems.push(problem);
        }
        problems
    }
}

pub async fn run() {
    // No raw path, token, identity, error text or capture contents are printed.
    let start = Instant::now();
    let capture = Capture::create().expect("private diagnostic capture unavailable");
    let mut live = Live::new(capture, start);
    let result = control(&mut live).await;
    assert_eq!(result.status(),"LOCAL_ORACLES_PASS","#287 local diagnostic nonpass; inspect privately retained capture; external custody remains UNVERIFIED");
}

#[cfg(test)]
mod controls {
    use super::*;
    #[test]
    fn actual_reader_timestamp_rejects_late_count_after_metrics_wait() {
        let mut reader = Reader::default();
        reader.record_frame(14_999);
        reader.record_frame(15_000);
        assert!(reader.by_deadline(2, 15_000));
        reader.record_frame(15_001);
        assert!(!reader.by_deadline(3, 15_000));
        assert!(!reader.by_deadline(2, 15_000));
    }
    #[test]
    fn actual_survival_precedence_preserves_exit_over_capture_and_child_io() {
        let mut result = Err(incomplete("CHILD_STATE_IO"));
        retain_problem(&mut result, Err(fail("OWN_DAEMON_EXIT")));
        retain_problem(&mut result, Err(incomplete("CAPTURE_IO")));
        assert_eq!(result, Err(fail("OWN_DAEMON_EXIT")));
        let mut missing = Ok(());
        retain_problem(&mut missing, Err(incomplete("CAPTURE_IO")));
        assert_eq!(missing, Err(incomplete("CAPTURE_IO")));
    }
    #[test]
    fn final_completed_probe_failures_survive_sibling_incomplete() {
        let base = Counters {
            dropped: 0,
            closes: 0,
            capture_complete: true,
        };
        let mut r = Reader::default();
        r.record_frame(1);
        let result = final_draining_outcome(
            Err(incomplete("HTTP_PROBE_DEADLINE")),
            Ok(false),
            Ok(json!({"ws_outbound_dropped":0,"ws_slow_consumer_closes":0})),
            Ok(r.clone()),
            base,
            1,
            15_000,
        );
        assert_eq!(result, Err(fail("DRAINING_SESSION_REMOVED")));
        let result = final_draining_outcome(
            Ok(json!({})),
            Err(incomplete("HTTP_PROBE_BODY_LIMIT")),
            Ok(json!({"ws_outbound_dropped":1,"ws_slow_consumer_closes":0})),
            Ok(r),
            base,
            1,
            15_000,
        );
        assert_eq!(result, Err(fail("DRAINING_DROP_OR_CLOSE")));
    }
    #[test]
    fn real_cleanup_adjudicator_keeps_exit_and_incomplete_custody_separately() {
        for error in ["CHILD_CLEANUP_CAPTURE_IO", "CHILD_IDENTITY_CLEANUP_IO"] {
            let mut receipt = DiagnosticCleanup {
                pid: 1,
                reaped: true,
                deliberate_termination: Some(false),
                exit: Some("observed exit".into()),
                capture_complete: error != "CHILD_CLEANUP_CAPTURE_IO",
                identity_removed: error != "CHILD_IDENTITY_CLEANUP_IO",
                errors: vec![error],
            };
            let problems = child_cleanup_problems(&receipt);
            assert!(problems.contains(&fail("OWN_DAEMON_EXIT")));
            assert!(problems.contains(&incomplete(error)));
            let mut trace = Transcript {
                cleanup_complete: false,
                ..Default::default()
            };
            trace.problems = problems;
            assert_eq!(trace.status(), "FAIL");
            receipt.deliberate_termination = Some(true);
            trace.problems = child_cleanup_problems(&receipt);
            assert_eq!(trace.status(), "INCOMPLETE");
            let unknown = DiagnosticCleanup {
                pid: 2,
                reaped: false,
                deliberate_termination: None,
                exit: None,
                capture_complete: false,
                identity_removed: false,
                errors: vec!["CHILD_STATE_IO"],
            };
            trace.problem(fail("OWN_DAEMON_EXIT"));
            trace.problems.extend(child_cleanup_problems(&unknown));
            assert_eq!(trace.status(), "FAIL");
            assert!(trace
                .problems
                .contains(&incomplete("OWN_CHILD_REAP_UNPROVEN")));
        }
    }
    struct Fake {
        now: u64,
        waves: Vec<(Arm, u64)>,
        n: u64,
        admitted: bool,
        drop_control: bool,
        counter_capture_failure: bool,
        mixed_failure: bool,
        cleaned: bool,
        checkpoints: usize,
        budget_end: u64,
    }
    impl Fake {
        fn new(n: u64) -> Self {
            Self {
                now: 0,
                waves: Vec::new(),
                n,
                admitted: false,
                drop_control: false,
                counter_capture_failure: false,
                mixed_failure: false,
                cleaned: false,
                checkpoints: 0,
                budget_end: 0,
            }
        }
    }
    fn complete_wave(arm: Arm, n: u64) -> Wave {
        Wave {
            arm,
            ordinal: n,
            capture_complete: true,
            requests: (0..64)
                .map(|i| RequestOutcome {
                    ordinal: i,
                    state: RequestState::Complete,
                    status: Some(200),
                    entered_ms: Some(1),
                    headers_ms: Some(2),
                    eof_ms: Some(3),
                    body_bytes: 2,
                    body_sha256: Some("inert hash".into()),
                })
                .collect(),
        }
    }
    impl Harness for Fake {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn checkpoint(&mut self, trace: &Transcript) -> Result<()> {
            self.checkpoints += 1;
            self.admitted |= trace.phases.contains(&"matched_replay_admitted");
            Ok(())
        }
        async fn setup(&mut self, end: u64) -> Result<()> {
            assert_eq!(end, 80_000);
            self.now = 1000;
            Ok(())
        }
        async fn counters(&mut self, arm: Arm, _end: u64) -> Result<Counters> {
            Ok(Counters {
                dropped: if arm == Arm::Stalled
                    && self.waves.iter().filter(|(a, _)| *a == arm).count() as u64 >= self.n
                    || arm == Arm::Draining
                        && self.drop_control
                        && self.waves.iter().any(|(a, _)| *a == arm)
                {
                    1
                } else {
                    0
                },
                closes: 0,
                capture_complete: !(self.counter_capture_failure
                    && arm == Arm::Draining
                    && self.waves.iter().any(|(a, _)| *a == arm)),
            })
        }
        async fn wave(&mut self, arm: Arm, n: u64, end: u64) -> Result<Wave> {
            assert!(self.now < end);
            self.waves.push((arm, n));
            self.now += 100;
            let mut w = complete_wave(arm, n);
            if self.mixed_failure {
                w.requests[0].state = RequestState::BodyError;
                w.requests[63].state = RequestState::Cancelled;
            }
            Ok(w)
        }
        async fn survival(&mut self) -> Result<()> {
            Ok(())
        }
        async fn finish_stalled(&mut self, _base: Counters, end: u64) -> Result<()> {
            assert_eq!(end, self.now + 70_000);
            self.now = if self.budget_end == 0 {
                self.now + 1000
            } else {
                self.budget_end
            };
            Ok(())
        }
        async fn finish_draining(
            &mut self,
            _base: Counters,
            expected: u64,
            end: u64,
        ) -> Result<()> {
            assert_eq!(expected, self.n * 64);
            assert!(self.now + 55_000 <= end);
            self.now += 55_000;
            Ok(())
        }
        async fn cleanup(&mut self, end: u64) -> Vec<Problem> {
            assert_eq!(end, 570_000);
            self.cleaned = true;
            Vec::new()
        }
    }
    #[tokio::test]
    async fn actual_controller_replays_complete_plan_and_cleans() {
        let mut f = Fake::new(3);
        let t = control(&mut f).await;
        assert_eq!(t.status(), "LOCAL_ORACLES_PASS");
        assert_eq!(
            f.waves,
            vec![
                (Arm::Stalled, 0),
                (Arm::Stalled, 1),
                (Arm::Stalled, 2),
                (Arm::Draining, 0),
                (Arm::Draining, 1),
                (Arm::Draining, 2)
            ]
        );
        assert!(f.admitted && f.cleaned && f.checkpoints > 4);
    }
    #[tokio::test]
    async fn actual_controller_refuses_overbudget_without_partial_replay() {
        let mut f = Fake::new(2);
        f.budget_end = WORK_MS - 55_000 - WAVE_MS;
        let t = control(&mut f).await;
        assert_eq!(t.status(), "INCONCLUSIVE");
        assert!(!f.admitted);
        assert!(f.cleaned);
        assert!(f.waves.iter().all(|(a, _)| *a == Arm::Stalled));
    }
    #[tokio::test]
    async fn actual_controller_accepts_exact_replay_budget_boundary() {
        let mut f = Fake::new(2);
        f.budget_end = WORK_MS - 55_000 - 2 * WAVE_MS;
        let t = control(&mut f).await;
        assert_eq!(t.status(), "LOCAL_ORACLES_PASS");
        assert!(f.admitted && f.cleaned);
    }
    #[tokio::test]
    async fn actual_controller_draining_drop_without_close_is_fail() {
        let mut f = Fake::new(1);
        f.drop_control = true;
        let t = control(&mut f).await;
        assert_eq!(t.status(), "FAIL");
        assert!(t.problems.contains(&fail("DRAINING_DROP_OR_CLOSE")));
        assert!(f.cleaned);
    }
    #[tokio::test]
    async fn actual_controller_measured_drop_survives_counter_capture_failure() {
        let mut f = Fake::new(1);
        f.drop_control = true;
        f.counter_capture_failure = true;
        let t = control(&mut f).await;
        assert_eq!(t.status(), "FAIL");
        assert!(t.problems.contains(&fail("DRAINING_DROP_OR_CLOSE")));
        assert!(f.cleaned);
        let mut f = Fake::new(1);
        f.counter_capture_failure = true;
        let t = control(&mut f).await;
        assert_eq!(t.status(), "INCOMPLETE");
        assert!(t.problems.contains(&incomplete("COUNTER_CAPTURE_IO")));
    }
    #[tokio::test]
    async fn actual_controller_body_failure_not_hidden_by_cancelled_sibling() {
        let mut f = Fake::new(1);
        f.mixed_failure = true;
        let t = control(&mut f).await;
        assert_eq!(t.status(), "FAIL");
        assert_eq!(f.waves.len(), 1);
        assert!(f.cleaned);
    }
    #[test]
    fn complete_body_and_all_sixty_four_outcomes_are_required() {
        let mut w = complete_wave(Arm::Stalled, 0);
        assert!(w.outcome().is_ok());
        w.requests[63].state = RequestState::Headers;
        assert_eq!(w.outcome().unwrap_err().class, Class::Incomplete);
        w.requests[63].state = RequestState::BodyError;
        assert_eq!(w.outcome().unwrap_err().class, Class::Fail);
        w.requests.pop();
        assert_eq!(w.outcome().unwrap_err().class, Class::Incomplete);
    }
    #[test]
    fn observed_failure_survives_incomplete_cleanup_and_evidence() {
        let mut t = Transcript::default();
        t.problem(fail("HTTP_PUBLISH_ORACLE"));
        t.problem(incomplete("CAPTURE_IO"));
        assert_eq!(t.status(), "FAIL");
        assert!(!t.cleanup_complete);
    }
    #[test]
    fn real_wire_classifier_requires_close_1013_not_eof_or_reset() {
        use tokio_tungstenite::tungstenite::{
            protocol::{frame::coding::CloseCode, CloseFrame},
            Error,
        };
        let close = |code| {
            Some(Ok(Message::Close(Some(CloseFrame {
                code,
                reason: "inert".into(),
            }))))
        };
        assert_eq!(
            wire_observation(close(CloseCode::Again)).unwrap(),
            WireObservation::Close1013
        );
        for value in [
            close(CloseCode::Normal),
            Some(Ok(Message::Close(None))),
            None,
            Some(Err(Error::ConnectionClosed)),
        ] {
            assert_eq!(wire_observation(value).unwrap_err().class, Class::Fail);
        }
        assert_eq!(
            wire_observation(Some(Ok(Message::Text("buffered".into())))).unwrap(),
            WireObservation::Buffered
        );
    }
    #[test]
    fn body_status_timeout_and_capture_limits_keep_distinct_outcomes() {
        for state in [
            RequestState::RequestError,
            RequestState::BodyError,
            RequestState::Timeout,
            RequestState::Non200,
        ] {
            let mut w = complete_wave(Arm::Stalled, 0);
            w.requests[0].state = state;
            assert_eq!(w.outcome().unwrap_err().class, Class::Fail);
        }
        let mut w = complete_wave(Arm::Stalled, 0);
        w.requests[0].state = RequestState::BodyLimit;
        assert_eq!(w.outcome().unwrap_err().class, Class::Incomplete);
        w.requests[0].status = Some(503);
        assert_eq!(w.outcome().unwrap_err().class, Class::Fail);
        w.capture_complete = false;
        assert_eq!(w.outcome().unwrap_err().class, Class::Fail);
    }
    #[test]
    fn private_capture_refuses_collision_and_preserves_nonce_in_each_record() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("capture");
        private_directory(&root).unwrap();
        assert!(private_directory(&root).is_err());
        let mut c = Capture {
            root: root.clone(),
            next: 0,
            nonce: "inert-nonce".into(),
        };
        c.write("control", &json!({"only":"inert"})).unwrap();
        let path = root.join("000000-control.json");
        let v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(v["nonce"], "inert-nonce");
        assert!(diagnostic_file(&path).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            assert_eq!(
                std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let link = temp.path().join("alias");
            symlink(&root, &link).unwrap();
            assert!(existing_directory(&link).is_err());
        }
    }
}
