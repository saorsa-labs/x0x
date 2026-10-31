//! ADR 0109 H-S3-home (D81 gate, #1571): the released v0.45.0 and v0.46.1
//! daemons on candidate data directories that hold the S3 Home placeholder.
//!
//! The data directories are the `tests/fixtures/h_s3_home` fixture, written
//! by the candidate's own arming path with Home activation on. For each
//! variant, on a copy of the directory, the released binary starts with no
//! network peers, waits [`wait`] (past v0.46.1's 90 s
//! `HOME_POINTER_SYNC_WAIT`), stops, starts again, waits, and stops.
//!
//! A variant passes only if, in both runs: the binary starts and stays up;
//! the API answers; the group-ID set stays the same; `home.json` stays
//! byte-identical, or stays absent; the Home group has no Active seat in
//! either file or in `GET /groups/:id/members`; its state revision does not
//! move; `POST /groups/:id/invite` and `POST /home/seat` get an HTTP
//! refusal; and the S3 sidecar bytes do not change.
//!
//! # What the released binaries do (measured 31 Oct 2026)
//!
//! The gate also asserts these measured steps, so a change in them fails
//! the gate and somebody must look again:
//!
//! 1. Run 1 strips the placeholder's Home metadata. Released
//!    `verify_restored_home_records` logs "restored Home metadata is
//!    unsigned ... stripping", because the all-Removed roster does not
//!    match the sealed state hash. After each run the
//!    `home-suite-groups.json` entry has no `home` field.
//! 2. An owner install (`owner_install` in the manifest) seals no fresh
//!    Home. The now unstamped group matches `is_home_candidate`, so the
//!    crash-recovery adoption step calls `stamp_and_seal_home`. That fails
//!    the zero-active-admins invariant ("Home metadata seal failed:
//!    invariant violation ... zero active admins") in each run, and the
//!    step returns `Done` before the fresh-create step. The device install
//!    makes no seal attempt. `home.json` does not change in any variant.
//! 3. A released save rewrites the `named_groups.json` entry in its #451
//!    form (an empty roster and the default admission). A released load
//!    lets the `home-suite-groups.json` entry win. Run 2 loads that #451
//!    form, and `GET /groups/:id/members` still shows no Active member, so
//!    the rewrite is inert. The gate requires the #451 form after each run.
//!
//! # Divergence from ADR 0109 §4
//!
//! ADR 0109 §4 "Risk" predicted that the owner-install variants fail:
//! released `find_home` needs an Active seat, so provisioning would create
//! a fresh Home. The 29 Oct 2026 ruling pinned that failure only "if the
//! test confirms this". The test does not confirm it: the released adoption
//! step fails closed (step 2), so no fresh Home is created. The Engineer
//! ruled on 31 Oct 2026 to remove the pin and to assert steps 1 to 3. The
//! gate pins no expected failure, and a manifest `expected_failure: true`
//! fails it.
//!
//! The binaries are installed by `scripts/ci/prepare-released-h-s3-home.sh`
//! before the loopback-only test namespace starts. The tests are ignored
//! and run in their own CI job (`--run-ignored ignored-only`).

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const FIXTURE: &str = "tests/fixtures/h_s3_home";

/// Real time per run: past v0.46.1's `HOME_POINTER_SYNC_WAIT` (90 s).
fn wait() -> Duration {
    let secs = std::env::var("X0X_H_S3_HOME_WAIT_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(150);
    Duration::from_secs(secs)
}

/// The fixture directory; `X0X_H_S3_HOME_FIXTURE` overrides it to try
/// other placeholder bytes.
fn fixture() -> PathBuf {
    std::env::var("X0X_H_S3_HOME_FIXTURE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root().join(FIXTURE))
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn released_bin(tag: &str, env: &str) -> PathBuf {
    let path = std::env::var(env)
        .map(PathBuf::from)
        .unwrap_or_else(|_| root().join("target/released-pinned").join(tag).join("x0xd"));
    assert!(
        path.is_file(),
        "released x0xd {tag} is not prepared ({}). Run \
         scripts/ci/prepare-released-h-s3-home.sh, or set {env}.",
        path.display()
    );
    path
}

fn sha_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn file_sha(path: &Path) -> Option<String> {
    fs::read(path).ok().map(|bytes| sha_hex(&bytes))
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create copy dir");
    for entry in fs::read_dir(from).expect("read fixture dir") {
        let entry = entry.expect("fixture entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy fixture file");
        }
    }
}

fn tail(path: &Path) -> String {
    let Ok(mut file) = fs::File::open(path) else {
        return String::new();
    };
    let len = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    if len > 4000 {
        let _ = file.seek(SeekFrom::End(-4000));
    }
    let mut buf = String::new();
    let _ = file.read_to_string(&mut buf);
    buf
}

/// The form of the Home group's entry in `named_groups.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NamedForm {
    /// The file has no entry for the group.
    Absent,
    /// A non-empty roster with no Active member (the candidate's form).
    SeatsNoOne,
    /// The released #451 form: an empty roster and the default admission.
    Released451,
    /// Any other roster: a released load can seat someone from it.
    SeatsSomeone,
}

/// What the files of one data directory say about the Home group.
#[derive(Debug)]
struct DiskView {
    group_ids: BTreeSet<String>,
    home_json: Option<String>,
    sidecars: BTreeSet<(String, String)>,
    /// Per legacy view: the group's state revision.
    revisions: Vec<Option<u64>>,
    /// The `home-suite-groups.json` entry seats no one.
    suite_inert: bool,
    /// The `home-suite-groups.json` entry still has `home` metadata.
    suite_home: bool,
    named: NamedForm,
}

fn load_map(path: &Path) -> serde_json::Map<String, Value> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).expect("legacy view parses"),
        Err(_) => serde_json::Map::new(),
    }
}

/// The group's entry seats no one: a non-empty roster with no Active
/// member, so no Active admin either (an empty roster seats the creator
/// on a released load).
fn seats_no_one(entry: &Value) -> bool {
    entry["members_v2"].as_object().is_some_and(|members| {
        !members.is_empty() && members.values().all(|member| member["state"] != "active")
    })
}

/// The released #451 form of an OwnerCertified entry in `named_groups.json`
/// (`legacy_safe_placeholder`): an empty roster and the default admission.
fn is_released_451_form(entry: &Value) -> bool {
    entry["members_v2"]
        .as_object()
        .is_some_and(serde_json::Map::is_empty)
        && entry["policy"]["admission"].is_string()
}

fn disk_view(data: &Path, group_key: &str) -> DiskView {
    let named = load_map(&data.join("named_groups.json"));
    let suite = load_map(&data.join("home-suite-groups.json"));
    let suite_entry = suite.get(group_key);
    let named_form = match named.get(group_key) {
        None => NamedForm::Absent,
        Some(entry) if seats_no_one(entry) => NamedForm::SeatsNoOne,
        Some(entry) if is_released_451_form(entry) => NamedForm::Released451,
        Some(_) => NamedForm::SeatsSomeone,
    };
    let revisions = [&named, &suite]
        .iter()
        .map(|map| {
            map.get(group_key)
                .and_then(|e| e["state_revision"].as_u64())
        })
        .collect();
    let mut sidecars = BTreeSet::new();
    if let Ok(entries) = fs::read_dir(data.join("group-recovery")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            sidecars.insert((name, file_sha(&entry.path()).unwrap_or_default()));
        }
    }
    DiskView {
        group_ids: named.keys().chain(suite.keys()).cloned().collect(),
        home_json: file_sha(&data.join("home.json")),
        sidecars,
        revisions,
        suite_inert: suite_entry.is_some_and(seats_no_one),
        suite_home: suite_entry.is_some_and(|entry| !entry["home"].is_null()),
        named: named_form,
    }
}

/// The fixture form: both entries seat no one and the Home-Suite entry
/// has the S3 placeholder's `home` metadata.
fn fixture_problems(view: &DiskView) -> Vec<String> {
    let mut problems = Vec::new();
    if !view.suite_inert {
        problems.push("home-suite-groups.json: the Home group seats someone".to_string());
    }
    if !view.suite_home {
        problems.push("home-suite-groups.json: no Home metadata to strip".to_string());
    }
    if view.named != NamedForm::SeatsNoOne {
        problems.push(format!("named_groups.json: {:?}", view.named));
    }
    problems
}

/// The files after a released run: step 1 (Home metadata stripped) and
/// step 3 (the #451 rewrite, inert behind an inert Home-Suite entry).
fn after_run_problems(view: &DiskView, run: usize) -> Vec<String> {
    let mut problems = Vec::new();
    if !view.suite_inert {
        problems.push(format!(
            "run {run}: home-suite-groups.json: the Home group seats someone"
        ));
    }
    if view.suite_home {
        problems.push(format!(
            "run {run}: home-suite-groups.json kept the unsigned Home metadata (step 1)"
        ));
    }
    if view.named != NamedForm::Released451 {
        problems.push(format!(
            "run {run}: named_groups.json is {:?}, not the released #451 form (step 3)",
            view.named
        ));
    }
    problems
}

/// The released log lines of one run: step 1 (strip, run 1 only; run 2
/// loads the stripped entry) and step 2 (an owner install fails the
/// adoption seal; a device install does not try it).
fn log_problems(home: &Path, run: usize, owner_install: bool, group_key: &str) -> Vec<String> {
    let mut log = fs::read_to_string(home.join(format!("stdout-{run}.log"))).unwrap_or_default();
    log.push_str(&fs::read_to_string(home.join(format!("stderr-{run}.log"))).unwrap_or_default());
    let lines: Vec<&str> = log
        .lines()
        .filter(|line| line.contains(group_key))
        .collect();
    let stripped = lines.iter().any(|line| {
        line.contains("restored Home metadata is unsigned") && line.contains("stripping")
    });
    let seal_failed = lines.iter().any(|line| {
        line.contains("Home metadata seal failed: invariant violation")
            && line.contains("zero active admins")
    });
    let seal_tried = lines
        .iter()
        .any(|line| line.contains("Home metadata seal") || line.contains("adopting unstamped"));
    let mut problems = Vec::new();
    if run == 1 && !stripped {
        problems.push(format!(
            "run {run}: no \"restored Home metadata is unsigned ... stripping\" line (step 1)"
        ));
    }
    if owner_install && !seal_failed {
        problems.push(format!(
            "run {run}: owner install: no zero-active-admins seal failure (step 2)"
        ));
    }
    if !owner_install && seal_tried {
        problems.push(format!(
            "run {run}: device install tried the Home adoption seal (step 2)"
        ));
    }
    problems
}

struct Daemon {
    child: Child,
    api: String,
    token: String,
    stderr: PathBuf,
}

impl Daemon {
    /// SIGTERM, then a kill after 20 s.
    fn stop(mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(bin: &Path, home: &Path, run: usize) -> Result<Daemon, String> {
    let data = home.join("data");
    let udp = UdpSocket::bind("127.0.0.1:0")
        .and_then(|socket| socket.local_addr())
        .map(|addr| addr.port())
        .map_err(|error| format!("udp port: {error}"))?;
    let config = home.join("config.toml");
    let text = format!(
        "bind_address = \"127.0.0.1:{udp}\"\n\
         api_address = \"127.0.0.1:0\"\n\
         data_dir = \"{}\"\n\
         identity_dir = \"{}\"\n\
         network_id = \"h-s3-home\"\n\
         mdns_enabled = false\n\
         port_mapping_enabled = false\n\
         rendezvous_enabled = false\n\
         bootstrap_peers = []\n\
         [update]\n\
         enabled = false\n",
        data.display(),
        data.join("identity").display(),
    );
    fs::write(&config, text).map_err(|error| format!("config: {error}"))?;
    let _ = fs::remove_file(data.join("api.port"));
    let stderr = home.join(format!("stderr-{run}.log"));
    let child = Command::new(bin)
        .arg("--config")
        .arg(&config)
        .args([
            "--no-hard-coded-bootstrap",
            "--disable-peer-cache",
            "--skip-update-check",
        ])
        .env("HOME", home)
        .env("X0X_HOME", home)
        .stdout(Stdio::from(
            fs::File::create(home.join(format!("stdout-{run}.log"))).map_err(|e| e.to_string())?,
        ))
        .stderr(Stdio::from(
            fs::File::create(&stderr).map_err(|e| e.to_string())?,
        ))
        .spawn()
        .map_err(|error| format!("spawn {}: {error}", bin.display()))?;
    let mut daemon = Daemon {
        child,
        api: String::new(),
        token: String::new(),
        stderr,
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(Some(status)) = daemon.child.try_wait() {
            return Err(format!(
                "exited {status} before the API came up\n{}",
                tail(&daemon.stderr)
            ));
        }
        if let Ok(addr) = fs::read_to_string(data.join("api.port")) {
            if addr.trim().parse::<SocketAddr>().is_ok() {
                daemon.api = format!("http://{}", addr.trim());
                break;
            }
        }
        if Instant::now() > deadline {
            let message = format!("API did not come up\n{}", tail(&daemon.stderr));
            daemon.stop();
            return Err(message);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    daemon.token = fs::read_to_string(data.join("api-token"))
        .map(|token| token.trim().to_string())
        .unwrap_or_default();
    Ok(daemon)
}

async fn request(daemon: &Daemon, post: Option<Value>, path: &str) -> (u16, Value) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()
        .expect("client");
    let url = format!("{}{path}", daemon.api);
    let builder = match &post {
        Some(body) => client.post(url).json(body),
        None => client.get(url),
    };
    match builder.bearer_auth(&daemon.token).send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            (status, response.json().await.unwrap_or(Value::Null))
        }
        Err(error) => (0, json!({ "error": error.to_string() })),
    }
}

/// The group IDs that the running daemon lists. A daemon that does not
/// answer `200` with a `groups` array fails the check.
async fn api_group_ids(daemon: &Daemon) -> Result<BTreeSet<String>, String> {
    let (status, body) = request(daemon, None, "/groups").await;
    let groups = body["groups"]
        .as_array()
        .filter(|_| status == 200)
        .ok_or_else(|| format!("GET /groups: {status} {body}"))?;
    Ok(groups
        .iter()
        .filter_map(|group| {
            group["group_id"]
                .as_str()
                .or_else(|| group["id"].as_str())
                .map(str::to_string)
        })
        .collect())
}

/// A mutating request must get an HTTP refusal. Status `0` means that no
/// daemon answered, which is not a refusal.
fn refused(status: u16) -> bool {
    (400..600).contains(&status)
}

/// The live checks of one run: the API answers, no new group, invite mint
/// and Home seat refused, the daemon stays up through the wait, and the
/// members view seats no one (step 3: the Home-Suite entry wins the load).
async fn live_checks(daemon: &mut Daemon, group_key: &str, run: usize, problems: &mut Vec<String>) {
    let before = api_group_ids(daemon).await;
    let (status, body) = request(
        daemon,
        Some(json!({ "expiry_secs": 3600 })),
        &format!("/groups/{group_key}/invite"),
    )
    .await;
    if !refused(status) {
        problems.push(format!("run {run}: invite not refused: {status} {body}"));
    }
    let (status, body) = request(
        daemon,
        Some(json!({ "agent_id": "c5".repeat(32) })),
        "/home/seat",
    )
    .await;
    if !refused(status) {
        problems.push(format!(
            "run {run}: POST /home/seat not refused: {status} {body}"
        ));
    }
    tokio::time::sleep(wait()).await;
    if !matches!(daemon.child.try_wait(), Ok(None)) {
        problems.push(format!(
            "run {run}: the daemon exited during the wait\n{}",
            tail(&daemon.stderr)
        ));
        return;
    }
    let after = api_group_ids(daemon).await;
    match (&before, &after) {
        (Ok(before), Ok(after)) if before == after => {}
        _ => problems.push(format!(
            "run {run}: the group set moved or did not answer: {before:?} -> {after:?}"
        )),
    }
    let (status, body) = request(daemon, None, &format!("/groups/{group_key}/members")).await;
    let active = body["members"].as_array().map(|members| {
        members
            .iter()
            .filter(|member| member["state"] == "active")
            .count()
    });
    if status != 200 || active != Some(0) {
        problems.push(format!(
            "run {run}: GET /groups/:id/members seats someone or did not answer: {status} {body}"
        ));
    }
}

/// One variant on one binary: the list of failed checks.
async fn run_variant(
    bin: PathBuf,
    tag: &str,
    name: String,
    group_key: String,
    owner_install: bool,
) -> Vec<String> {
    let home = root().join("target/h-s3-home").join(tag).join(&name);
    let _ = fs::remove_dir_all(&home);
    let data = home.join("data");
    copy_dir(&fixture().join(&name), &data);
    let baseline = disk_view(&data, &group_key);
    let problems = fixture_problems(&baseline);
    if !problems.is_empty() {
        return problems
            .into_iter()
            .map(|p| format!("fixture: {p}"))
            .collect();
    }
    let mut problems = Vec::new();
    for run in 1..=2 {
        let mut daemon = match start(&bin, &home, run) {
            Ok(daemon) => daemon,
            Err(error) => {
                problems.push(format!("run {run}: the binary did not start: {error}"));
                break;
            }
        };
        live_checks(&mut daemon, &group_key, run, &mut problems).await;
        daemon.stop();
        let view = disk_view(&data, &group_key);
        problems.extend(after_run_problems(&view, run));
        problems.extend(log_problems(&home, run, owner_install, &group_key));
        if view.group_ids != baseline.group_ids {
            problems.push(format!(
                "run {run}: group-ID set {:?} -> {:?}",
                baseline.group_ids, view.group_ids
            ));
        }
        if view.home_json != baseline.home_json {
            problems.push(format!("run {run}: home.json changed or appeared"));
        }
        if view.sidecars != baseline.sidecars {
            problems.push(format!("run {run}: the S3 sidecar bytes changed"));
        }
        if view.revisions != baseline.revisions {
            problems.push(format!(
                "run {run}: state revision {:?} -> {:?}",
                baseline.revisions, view.revisions
            ));
        }
    }
    problems
}

async fn gate(tag: &str, env: &str) {
    let bin = released_bin(tag, env);
    let manifest: Value = serde_json::from_slice(
        &fs::read(fixture().join("manifest.json")).expect("fixture manifest"),
    )
    .expect("manifest parses");
    let variants = manifest.as_object().expect("manifest: variant -> entry");
    let mut tasks = tokio::task::JoinSet::new();
    for (name, variant) in variants {
        // Engineer ruling, 31 Oct 2026: the gate pins no expected failure.
        assert!(
            !variant["expected_failure"].as_bool().unwrap_or(false),
            "manifest pins {name} as an expected failure; the gate pins none"
        );
        let group_key = variant["group_key"]
            .as_str()
            .expect("group_key")
            .to_string();
        let owner_install = variant["owner_install"].as_bool().expect("owner_install");
        let (bin, tag, name) = (bin.clone(), tag.to_string(), name.clone());
        tasks.spawn(async move {
            let problems = run_variant(bin, &tag, name.clone(), group_key, owner_install).await;
            (name, problems)
        });
    }
    let mut report = serde_json::Map::new();
    let mut all_pass = true;
    while let Some(joined) = tasks.join_next().await {
        let (name, problems) = joined.expect("variant task");
        let verdict = if problems.is_empty() { "pass" } else { "FAIL" };
        all_pass &= problems.is_empty();
        report.insert(name, json!({ "verdict": verdict, "problems": problems }));
    }
    let report = Value::Object(report);
    let out = root()
        .join("target/h-s3-home")
        .join(format!("{tag}-report.json"));
    let _ = fs::write(&out, serde_json::to_vec_pretty(&report).unwrap_or_default());
    println!("H-S3-home {tag}: {report:#}");
    assert!(
        all_pass,
        "H-S3-home {tag} (Home activation stays off): {report:#}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real-time released-binary gate; own CI job (#1571)"]
async fn h_s3_home_released_v0_45_0() {
    gate("v0.45.0", "X0X_V045_BIN").await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real-time released-binary gate; own CI job (#1571)"]
async fn h_s3_home_released_v0_46_1() {
    gate("v0.46.1", "X0X_V0461_BIN").await;
}
