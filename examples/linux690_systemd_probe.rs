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
