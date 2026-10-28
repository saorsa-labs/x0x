//! Invoked only by the isolated Linux systemd fixture. Uses the real private
//! parent, real exec, real wait/reap and real pair renames on disposable files.
#![cfg(test)]
use super::*;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn wait(path: &Path) {
    let bound = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < bound, "missing {}", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn isolated() {
    // SAFETY: geteuid only reads process identity.
    assert_ne!(unsafe { libc::geteuid() }, 0);
    let parent = std::env::var("X0X_FIXTURE_PARENT_NETNS").unwrap();
    assert_ne!(
        fs::read_link("/proc/self/ns/net")
            .unwrap()
            .to_str()
            .unwrap(),
        parent
    );
    let output = Command::new("/usr/sbin/ip")
        .args(["-j", "link"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let links: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(links.as_array().unwrap().len(), 1);
    assert_eq!(links[0]["ifname"], "lo");
    let status = fs::read_to_string("/proc/self/status").unwrap();
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let value = status
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{name}:")))
            .unwrap();
        assert_eq!(u64::from_str_radix(value.trim(), 16).unwrap(), 0);
    }
    assert!(status.lines().any(|l| l == "NoNewPrivs:\t1"));
}

fn prepare(root: &Path, case: &str) -> (recovery::Host, Trial) {
    let fixture = PathBuf::from(std::env::var_os("X0X_LAUNCHER_FIXTURE_BIN").unwrap());
    let daemon = root.join("x0xd");
    let cli = root.join("x0x");
    fs::copy(&fixture, &daemon).unwrap();
    fs::copy(&fixture, &cli).unwrap();
    let env: BTreeMap<String, String> = [
        ("X0X_LAUNCHER_CASE".into(), case.into()),
        (
            "X0X_FIXTURE_PARENT_NETNS".into(),
            std::env::var("X0X_FIXTURE_PARENT_NETNS").unwrap(),
        ),
    ]
    .into_iter()
    .collect();
    let argv = vec![
        daemon.to_string_lossy().into_owned(),
        "--launcher-child".into(),
        root.to_string_lossy().into_owned(),
    ];
    let mut old = Command::new(&daemon)
        .args(argv.iter().skip(1))
        .env_clear()
        .envs(&env)
        .current_dir(root)
        .spawn()
        .unwrap();
    wait(&root.join("old-ready.json"));
    let old_identity = child::identity(old.id()).unwrap();
    let artifact = |target: PathBuf| {
        let backup = target.with_extension("old");
        let staged = target.with_extension("new");
        fs::copy(&target, &backup).unwrap();
        fs::copy(&fixture, &staged).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&staged)
            .unwrap()
            .write_all(b"candidate bytes")
            .unwrap();
        let output = Command::new(&staged)
            .arg("--upgrade-probe")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "probe must pass before the exec fault"
        );
        let probe: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(probe["version"], env!("CARGO_PKG_VERSION"));
        let plan = journal::ArtifactPlan {
            target_path: target.clone(),
            staged_path: staged.clone(),
            backup_path: backup.clone(),
            previous_sha256: filesystem::hash(&backup).unwrap(),
            candidate_sha256: filesystem::hash(&staged).unwrap(),
        };
        fs::rename(staged, target).unwrap();
        plan
    };
    let daemon_plan = artifact(daemon.clone());
    let cli_plan = artifact(cli);
    let participant = journal::Participant {
        instance_id: "alice".into(),
        executable: daemon,
        data_root: root.into(),
        identity_root: root.into(),
        argv,
        cwd: root.into(),
        env,
        restart: journal::RestartBinding {
            mode: journal::RestartOwner::LauncherChild,
            supervised_exit_code: None,
            supervision_signal: None,
            launchd_verified: None,
            systemd_verified: None,
            launcher: Some(journal::LauncherBinding {
                executable: std::env::current_exe().unwrap(),
                argv: std::env::args().collect(),
                pid: Some(std::process::id()),
                process_start: Some(child::identity(std::process::id()).unwrap().start),
                boot_id: old_identity.boot.clone(),
                manager_exit_code: 0,
            }),
        },
        old_pid: Some(old_identity.pid),
        process_start: Some(old_identity.start),
        boot_id: old_identity.boot,
        was_running: true,
    };
    let progress = journal::ArtifactProgress {
        swapped: true,
        restored: false,
        observed_sha256: None,
    };
    let record = journal::JournalRecord {
        schema_version: 1,
        record_kind: "journal".into(),
        transaction_id: "lifecycle-fixture".into(),
        sequence: 1,
        generation: 1,
        plan: journal::FrozenPlan {
            previous_version: "0.0.1".into(),
            candidate_version: env!("CARGO_PKG_VERSION").into(),
            manifest_sha256: [7; 32],
            daemon: daemon_plan,
            cli: cli_plan,
            participants: vec![participant],
        },
        phase: journal::Phase::SwappedCli,
        cause: None,
        daemon_progress: progress.clone(),
        cli_progress: progress,
    };
    journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
    fs::write(
        root.join("independent-plan.json"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    let host = recovery::Host::new(root.into(), record).unwrap();
    let mut trial = Trial::new(
        host.binding().unwrap(),
        "alice".into(),
        &Clock::now().unwrap(),
    )
    .unwrap();
    let path = root.join("trial.json");
    // Missing receipt cannot start NEW while OLD is still alive.
    assert!(control::authorize(&host, &mut trial, &path, &[]).is_err());
    assert_eq!(trial.attempts, 0);
    let reaped =
        control::flush_and_reap(&host, &trial, &path, &mut old, "inert launcher fixture").unwrap();
    control::authorize(&host, &mut trial, &path, &[reaped]).unwrap();
    (host, trial)
}

#[test]
#[ignore = "only the isolated Linux systemd fixture may run this lifecycle"]
fn systemd() {
    isolated();
    let root = PathBuf::from(std::env::var_os("X0X_LAUNCHER_ROOT").unwrap())
        .canonicalize()
        .unwrap();
    let case = std::env::var("X0X_LAUNCHER_CASE").unwrap();
    let path = root.join("trial.json");
    if !root.join("first-invocation.json").exists() {
        fs::write(
            root.join("first-invocation.json"),
            serde_json::to_vec(&serde_json::json!({
            "pid": std::process::id(), "invocation": std::env::var("INVOCATION_ID").unwrap() }))
            .unwrap(),
        )
        .unwrap();
    }
    let (host, mut trial) = if case.starts_with("restart") && path.exists() {
        let record =
            serde_json::from_slice(&fs::read(root.join("independent-plan.json")).unwrap()).unwrap();
        let host = recovery::Host::new(root.clone(), record).unwrap();
        let trial = Trial::load(&path, &host.binding().unwrap(), "alice").unwrap();
        let deadline: u64 = fs::read_to_string(root.join("original-deadline"))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            trial.attempts, 1,
            "exec failure must be charged before the launcher dies"
        );
        assert_eq!(
            trial.deadline_ms, deadline,
            "same-boot restart must retain the budget"
        );
        (host, trial)
    } else {
        prepare(&root, &case)
    };
    if case == "exec" || case == "restart" {
        fs::set_permissions(
            &host.plan().daemon.target_path,
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    if case == "restart" && trial.attempts == 0 {
        fs::write(
            root.join("original-deadline"),
            trial.deadline_ms.to_string(),
        )
        .unwrap();
        trial.reserve(&path, &Clock::now().unwrap()).unwrap();
        assert!(child::Owned::spawn(
            &mut trial,
            &path,
            &host.plan().participants[0],
            &host.plan().candidate_version,
            host.plan().daemon.candidate_sha256
        )
        .unwrap()
        .is_none());
        // Crash after real exec failure, before the ordinary error-save path.
        std::process::exit(75);
    }
    let kill_parent = case == "restart-child" && trial.attempts == 0;
    if kill_parent {
        fs::write(
            root.join("original-deadline"),
            trial.deadline_ms.to_string(),
        )
        .unwrap();
    }
    // SAFETY: this signal handler only stores a lock-free atomic flag.
    unsafe {
        libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
    }
    let start = Clock::now().unwrap();
    let wall = Instant::now();
    let mut reported = false;
    let outcome = run::run_trial(
        &host,
        &path,
        &mut trial,
        || {
            Ok(Clock {
                boot: start.boot.clone(),
                ms: start.ms
                    + wall.elapsed().as_millis() as u64 * if case == "stop" { 1 } else { 100 },
            })
        },
        |_| {
            if !reported {
                fs::write(root.join("child-running"), b"yes")?;
                reported = true;
                if kill_parent {
                    std::process::exit(75);
                }
            }
            Ok(false)
        },
        || STOP.load(Ordering::Relaxed),
    )
    .unwrap();
    match outcome {
        run::Outcome::Stopped => {
            assert_eq!(case, "stop");
            assert_eq!(trial.attempts, 1);
            assert!(!root.join("restored-started.json").exists());
            assert_eq!(
                filesystem::hash(&host.plan().daemon.target_path).unwrap(),
                host.plan().daemon.candidate_sha256
            );
        }
        run::Outcome::Restored(mut child) => {
            wait(&root.join("restored-started.json"));
            assert!(child.exited().unwrap().is_none());
            for a in [&host.plan().daemon, &host.plan().cli] {
                assert_eq!(filesystem::hash(&a.target_path).unwrap(), a.previous_sha256);
                assert_eq!(filesystem::hash(&a.backup_path).unwrap(), a.previous_sha256);
            }
            assert_eq!(
                trial.attempts,
                if case.starts_with("restart") { 1 } else { 3 }
            );
            child.reap().unwrap();
        }
        run::Outcome::Provisional(_) => panic!("unhealthy fixture must not commit"),
    }
    fs::write(
        root.join("done.json"),
        serde_json::to_vec(&serde_json::json!({"case": case,
        "attempts": trial.attempts, "deadline_ms": trial.deadline_ms, "cause": trial.cause,
        "pid": std::process::id(), "invocation": std::env::var("INVOCATION_ID").unwrap()}))
        .unwrap(),
    )
    .unwrap();
}
