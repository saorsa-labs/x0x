use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use x0x::upgrade::restart::{readback_systemd_policy, SupervisionSignals, SystemdPolicyReadback};

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
    // Every invocation, including respawns, admits itself before fixture work.
    let isolation = sample_isolation()?;
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

fn main() {
    if let Err(error) = run() {
        eprintln!("linux690 probe failed: {error}");
        std::process::exit(2);
    }
}
