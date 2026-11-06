use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use x0x::upgrade::restart::{readback_systemd_policy, SupervisionSignals, SystemdPolicyReadback};
#[cfg(target_os = "linux")]
#[path = "../src/upgrade/journal.rs"]
mod journal;

#[derive(Serialize)]
struct VerdictRecord {
    schema: u32,
    invocation: u32,
    pid: u32,
    invocation_id: Option<String>,
    argv: Vec<String>,
    unix_ms: u128,
    exit_intent: &'static str,
    verdict: &'static str,
    unit: Option<String>,
    user_manager: Option<bool>,
    restart: Option<String>,
    template_version: Option<u32>,
    detail: Option<String>,
    isolation: serde_json::Value,
}

#[cfg(target_os = "linux")]
fn sample_isolation() -> io::Result<serde_json::Value> {
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::process::Command;

    let parent = std::env::var("X0X_FIXTURE_PARENT_NETNS").map_err(io::Error::other)?;
    let namespace = fs::read_link("/proc/self/ns/net")?
        .to_string_lossy()
        .into_owned();
    if namespace == parent || !parent.starts_with("net:[") {
        return Err(io::Error::other("fixture network namespace did not change"));
    }
    let ip = |args: &[&str]| -> io::Result<serde_json::Value> {
        let output = Command::new("/usr/sbin/ip").args(args).output()?;
        if !output.status.success() {
            return Err(io::Error::other("fixture ip observation failed"));
        }
        serde_json::from_slice(&output.stdout).map_err(io::Error::other)
    };
    let links = ip(&["-j", "link"])?;
    let routes = json!({
        "-4": ip(&["-4", "-j", "route", "show", "table", "all"] )?,
        "-6": ip(&["-6", "-j", "route", "show", "table", "all"] )?,
    });
    if links
        .as_array()
        .is_none_or(|rows| rows.len() != 1 || rows[0]["ifname"] != "lo")
        || ["-4", "-6"].iter().any(|family| {
            routes[family].as_array().is_none_or(|rows| {
                rows.iter().any(|row| {
                    row["dev"] != "lo" || row["dst"] == "default" || row.get("gateway").is_some()
                })
            })
        })
    {
        return Err(io::Error::other("fixture is not loopback-only"));
    }
    let status = fs::read_to_string("/proc/self/status")?;
    let fields: BTreeMap<_, _> = status
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name, value.trim()))
        .collect();
    let field = |name| {
        fields
            .get(name)
            .copied()
            .ok_or_else(|| io::Error::other("missing process status field"))
    };
    let identity = |name| -> io::Result<u32> {
        let ids = field(name)?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(io::Error::other)?;
        if ids.len() != 4 || ids.iter().any(|id| *id == 0 || *id != ids[0]) {
            return Err(io::Error::other("fixture identity was not dropped"));
        }
        Ok(ids[0])
    };
    let uid = identity("Uid")?;
    let gid = identity("Gid")?;
    if field("Groups")?
        .split_whitespace()
        .any(|group| group == "0")
        || field("NoNewPrivs")? != "1"
    {
        return Err(io::Error::other("fixture groups or no_new_privs unsafe"));
    }
    let mut capabilities = BTreeMap::new();
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let value = field(name)?;
        if u64::from_str_radix(value, 16).map_err(io::Error::other)? != 0 {
            return Err(io::Error::other("fixture capabilities were not dropped"));
        }
        capabilities.insert(name, value);
    }
    Ok(
        json!({"namespace": namespace, "namespace_changed": true, "links": links,
        "routes": routes, "uid": uid, "gid": gid, "capabilities": capabilities,
        "no_new_privs": 1}),
    )
}

#[cfg(not(target_os = "linux"))]
fn sample_isolation() -> io::Result<serde_json::Value> {
    Err(io::Error::other("systemd fixtures require isolated Linux"))
}

fn atomic_json(path: &Path, value: &impl Serialize) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("record has no parent"))?;
    let tmp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    let mut file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    fs::File::open(parent)?.sync_all()
}

fn claim_invocation(dir: &Path) -> io::Result<u32> {
    for invocation in 1..=8 {
        let claim = dir.join(format!("claim-{invocation}"));
        match OpenOptions::new().create_new(true).write(true).open(claim) {
            Ok(mut file) => {
                writeln!(file, "{}", std::process::id())?;
                file.sync_all()?;
                return Ok(invocation);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other("more than eight fixture invocations"))
}

fn wait_for(path: &Path, bound: Duration) -> io::Result<()> {
    let deadline = Instant::now() + bound;
    while Instant::now() < deadline {
        if path.try_exists()? {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("timed out waiting for {}", path.display()),
    ))
}

fn parse_args() -> io::Result<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    match (args.next().as_deref(), args.next(), args.next()) {
        (Some(flag), Some(path), None) if flag == "--artifact" => Ok(PathBuf::from(path)),
        _ => Err(io::Error::other("usage: x0x-linux690-probe --artifact DIR")),
    }
}

fn run() -> io::Result<()> {
    if let Some(result) = x0x::upgrade::verification_probe::run_if_requested() {
        return result.map_err(io::Error::other);
    }
    // Every invocation, including respawns, admits itself before fixture work.
    let isolation = sample_isolation()?;
    #[cfg(target_os = "linux")]
    if let Some(mode) = std::env::args()
        .nth(1)
        .filter(|arg| arg.starts_with("--launcher-"))
    {
        return launcher_fixture(&mode);
    }
    let artifact = parse_args()?;
    fs::create_dir_all(&artifact)?;
    let invocation = claim_invocation(&artifact)?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let argv: Vec<String> = std::env::args().collect();
    let signals = SupervisionSignals::sample();
    let readback = readback_systemd_policy(&signals, &executable, &argv);
    let (verdict, unit, user_manager, restart, template_version, detail) = match readback {
        SystemdPolicyReadback::Verified(unit) => (
            "verified",
            Some(unit.unit),
            Some(unit.user_manager),
            Some(unit.restart),
            unit.template_version,
            None,
        ),
        SystemdPolicyReadback::NotGuaranteed { detail } => {
            ("not_guaranteed", None, None, None, None, Some(detail))
        }
        SystemdPolicyReadback::StartRateWindowPending {
            detail,
            retry_after,
        } => (
            "start_rate_window_pending",
            None,
            None,
            None,
            None,
            Some(format!("{detail} (retry_after {retry_after:?})")),
        ),
        SystemdPolicyReadback::NotApplicable => (
            "not_applicable",
            None,
            None,
            None,
            None,
            Some("systemd supervision signal was not observed".to_string()),
        ),
    };
    let unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis();
    atomic_json(
        &artifact.join(format!("invocation-{invocation}.json")),
        &VerdictRecord {
            schema: 1,
            invocation,
            pid: std::process::id(),
            invocation_id: std::env::var("INVOCATION_ID")
                .ok()
                .filter(|v| !v.is_empty()),
            argv,
            unix_ms,
            exit_intent: if invocation == 1 {
                "clean_exit_after_release"
            } else {
                "wait_for_manager_stop"
            },
            verdict,
            unit,
            user_manager,
            restart,
            template_version,
            detail,
            isolation,
        },
    )?;
    if invocation == 1 {
        wait_for(&artifact.join("release-first"), Duration::from_secs(45))?;
        return Ok(());
    }
    loop {
        std::thread::park_timeout(Duration::from_secs(60));
    }
}

/// The launcher parent's identity inside a permit: pid, process start and
/// boot id, as the launcher's own `Identity` serializes them.
#[cfg(target_os = "linux")]
#[derive(serde::Deserialize)]
#[allow(dead_code)] // schema-only: present so a malformed permit fails to parse
struct FixtureParent {
    pid: u32,
    start: u64,
    boot: String,
}

/// The launcher's private fd-3 permit, duplicated here only as the fixture
/// child's read schema. `deny_unknown_fields` makes a launcher contract
/// change fail this fixture loudly instead of silently. The full
/// permit-versus-self verification stays in the launcher module, where its
/// tests live; this fixture refuses a permit for another process or
/// version, then acknowledges.
#[cfg(target_os = "linux")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // read schema only; the checks below bind what they need
struct FixturePermit {
    record: journal::BootRecord,
    parent: FixtureParent,
    root: PathBuf,
    executable: PathBuf,
    sha256: [u8; 32],
    version: String,
    argv: Vec<Vec<u8>>,
    cwd: PathBuf,
}

/// The daemon side of the private boot barrier: read the whole permit from
/// descriptor 3, refuse one that is not for this process and version, write
/// the boot record, then acknowledge with one byte. The activation-time
/// daemon runs this same exchange with full self-verification under
/// `ENABLED`.
#[cfg(target_os = "linux")]
fn candidate_boot_fixture(version: &str) -> io::Result<()> {
    use std::io::{BufRead, Read, Write};
    use std::os::unix::net::UnixStream;
    let marker = std::env::var_os("X0X_M2_BOOT_FD")
        .ok_or_else(|| io::Error::other("boot descriptor missing"))?;
    // No later child of this fixture may treat descriptor 3 as its own.
    std::env::remove_var("X0X_M2_BOOT_FD");
    if marker != "3" {
        return Err(io::Error::other("invalid private boot descriptor"));
    }
    // SAFETY: the launcher duplicated the boot channel onto descriptor 3
    // for this process; from_raw_fd takes the ownership this exchange
    // spends here.
    let mut reader =
        std::io::BufReader::new(unsafe { <UnixStream as std::os::fd::FromRawFd>::from_raw_fd(3) });
    reader
        .get_ref()
        .set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(1024 * 1024)
        .read_until(b'\n', &mut bytes)?;
    let permit: FixturePermit = serde_json::from_slice(&bytes)?;
    if permit.record.pid != std::process::id() || permit.version != version {
        return Err(io::Error::other("permit does not bind this child"));
    }
    // The real candidate records its boot before it acknowledges; the
    // fixture keeps the same order so the data root looks the same.
    journal::write_record(&permit.root.join(journal::BOOT_FILE_NAME), &permit.record)?;
    reader.get_mut().write_all(&[1])
}

/// The daemon side of the launcher's inert flush exchange. The receipt's
/// plan digest must equal the launcher's binding construction — SHA-256
/// over the JSON `[instance_id, plan]` pair — so the plan is parsed with
/// the real journal types; re-serializing a `Value` would reorder fields
/// and change the digest.
#[cfg(target_os = "linux")]
fn fixture_receipt(bytes: &[u8]) -> io::Result<serde_json::Value> {
    #[derive(serde::Deserialize)]
    struct Request {
        token: String,
        transaction_id: String,
        generation: u64,
        instance_id: String,
        plan: journal::FrozenPlan,
    }
    let r: Request = serde_json::from_slice(bytes)?;
    if r.token != "inert launcher fixture" {
        return Err(io::Error::other("bad fixture credential"));
    }
    use sha2::Digest;
    let pair = (r.instance_id.as_str(), &r.plan);
    let plan_sha256: [u8; 32] = sha2::Sha256::digest(serde_json::to_vec(&pair)?).into();
    Ok(serde_json::json!({
        "binding": {
            "transaction_id": r.transaction_id,
            "generation": r.generation,
            "plan_sha256": plan_sha256,
        },
        "receipt_id": "fixture-flush"
    }))
}

#[cfg(target_os = "linux")]
fn launcher_fixture(mode: &str) -> io::Result<()> {
    use std::io::{BufRead, Read};
    if mode == "--launcher-child" && std::env::var_os("X0X_M2_BOOT_FD").is_some() {
        candidate_boot_fixture(env!("CARGO_PKG_VERSION"))?;
        if std::env::var("X0X_LAUNCHER_CASE").as_deref() == Ok("crash") {
            std::process::exit(19);
        }
        loop {
            std::thread::park_timeout(Duration::from_secs(60));
        }
    }
    if mode != "--launcher-child" {
        return Err(io::Error::other("unknown launcher fixture"));
    }
    let root = PathBuf::from(
        std::env::args_os()
            .nth(2)
            .ok_or_else(|| io::Error::other("missing fixture root"))?,
    );
    if root.join("fixture-flush.json").exists() {
        atomic_json(
            &root.join("restored-started.json"),
            &serde_json::json!({"pid": std::process::id()}),
        )?;
        loop {
            std::thread::park_timeout(Duration::from_secs(60));
        }
    }
    let listener = std::os::unix::net::UnixListener::bind(root.join("upgrade-flush.sock"))?;
    atomic_json(
        &root.join("old-ready.json"),
        &serde_json::json!({"pid": std::process::id()}),
    )?;
    let (mut socket, _) = listener.accept()?;
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut bytes = Vec::new();
    std::io::BufReader::new(&mut socket)
        .take(1024 * 1024)
        .read_until(b'\n', &mut bytes)?;
    let receipt = fixture_receipt(&bytes)?;
    atomic_json(&root.join("fixture-flush.json"), &receipt)?;
    serde_json::to_writer(&mut socket, &serde_json::json!({"receipt": receipt}))?;
    socket.write_all(b"\n")
}

fn main() {
    if let Err(error) = run() {
        eprintln!("linux690 probe failed: {error}");
        std::process::exit(2);
    }
}
