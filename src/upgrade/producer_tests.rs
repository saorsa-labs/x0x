#![cfg(test)]
//! Tests of the gated prepare producer (#2012). Inert: temporary
//! directories only, no daemon and no network.
use super::*;
use crate::upgrade::restart::{LoadedLauncher, SystemdVerifiedUnit};
use std::collections::BTreeMap;

thread_local! {
    static STEPS: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) };
    static FAIL_INSTALL: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

pub(crate) fn step(name: &'static str) {
    STEPS.with(|steps| steps.borrow_mut().push(name));
}

pub(crate) fn fail_install(target: &Path) -> io::Result<()> {
    if FAIL_INSTALL.with(|fail| fail.borrow().as_deref() == Some(target)) {
        return Err(io::Error::other("injected install failure"));
    }
    Ok(())
}

// ---------------------------------------------------------------- the gate

struct Host {
    _dir: tempfile::TempDir,
    root: PathBuf,
    daemon: PathBuf,
    cli: PathBuf,
    anchor: PathBuf,
    dropin: PathBuf,
}

const COMMAND: &str = "x0x-launcher --host-root R --instance alice --plan-anchor A -- x0xd";

fn host() -> Host {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let daemon = root.join("x0xd");
    let cli = root.join("x0x");
    std::fs::write(&daemon, b"daemon").unwrap();
    std::fs::write(&cli, b"cli").unwrap();
    let anchor = root.join("install.anchor.json");
    let dropin = root.join(DROPIN_NAME);
    std::fs::write(
        &dropin,
        format!("[Service]\nExecStart=\nExecStart={COMMAND}\n"),
    )
    .unwrap();
    Host {
        _dir: dir,
        root,
        daemon,
        cli,
        anchor,
        dropin,
    }
}

fn plan(host: &Host) -> RestartPlan {
    RestartPlan {
        mode: RestartMode::SupervisedExit,
        supervised_exit_code: Some(0),
        supervision_signal: Some("INVOCATION_ID".into()),
        executable: host.daemon.clone(),
        argv: vec![host.daemon.to_string_lossy().into_owned()],
        cwd: host.root.clone(),
        data_root: host.root.clone(),
        api_addr: "127.0.0.1:9".parse().unwrap(),
        launchd_verified: None,
        systemd_verified: Some(SystemdVerifiedUnit {
            unit: "x0xd.service".into(),
            user_manager: false,
            restart: "always".into(),
            template_version: None,
            launcher: Some(LoadedLauncher {
                executable: host.root.join("x0x-launcher"),
                command: COMMAND.split(' ').map(String::from).collect(),
                trial: launcher_contract::TrialArgs {
                    host_root: host.root.clone(),
                    instance: "alice".into(),
                    plan_anchor: Some(host.anchor.clone()),
                },
            }),
        }),
    }
}

fn anchor_json(daemon: &Path, cli: &Path, participants: &[(&str, &Path)]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "record_kind": "plan_anchor",
        "daemon_target": daemon,
        "cli_target": cli,
        "participants": participants
            .iter()
            .map(|(id, root)| serde_json::json!({"instance_id": id, "data_root": root}))
            .collect::<Vec<_>>(),
    }))
    .unwrap()
}

struct FakeProbe {
    files: io::Result<UnitFiles>,
    anchor: Vec<u8>,
    capabilities: io::Result<Vec<String>>,
}

impl FakeProbe {
    fn open(host: &Host) -> Self {
        Self {
            files: Ok(UnitFiles {
                need_daemon_reload: false,
                dropins: vec![host.root.join("10-other.conf"), host.dropin.clone()],
            }),
            anchor: anchor_json(&host.daemon, &host.cli, &[("alice", &host.root)]),
            capabilities: Ok(vec![launcher_contract::TRIAL_CAPABILITY.into()]),
        }
    }
}

impl Probe for FakeProbe {
    fn unit_files(&self, _: &str, _: bool) -> io::Result<UnitFiles> {
        match &self.files {
            Ok(files) => Ok(files.clone()),
            Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
        }
    }
    fn anchor(&self, _: &Path) -> io::Result<plan_binding::Anchored> {
        plan_binding::Anchored::parse(self.anchor.clone())
    }
    fn capabilities(&self, _: &Path) -> io::Result<Vec<String>> {
        match &self.capabilities {
            Ok(found) => Ok(found.clone()),
            Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
        }
    }
}

fn closed_by(gate: Gate, reason: &str) {
    match gate {
        Gate::Closed(found) => assert!(found.contains(reason), "want {reason:?}, got {found:?}"),
        Gate::Open(_) => panic!("open, want closed by {reason:?}"),
    }
}

fn launcher(plan: &mut RestartPlan) -> &mut LoadedLauncher {
    plan.systemd_verified
        .as_mut()
        .unwrap()
        .launcher
        .as_mut()
        .unwrap()
}

/// Every gate check alone closes the gate (each row a mutation the test
/// kills), and all of them together open it.
#[test]
fn each_gate_check_alone_closes_the_gate() {
    let host = host();
    let open = evaluate(true, &plan(&host), &host.cli, &FakeProbe::open(&host));
    let Gate::Open(open) = open else {
        panic!("the full fixture must open the gate: {open:?}");
    };
    assert_eq!(open.anchor_path, host.anchor);
    assert_eq!(open.instance, "alice");

    closed_by(
        evaluate(false, &plan(&host), &host.cli, &FakeProbe::open(&host)),
        "dormant",
    );

    type PlanEdit = (fn(&mut RestartPlan, &Host), &'static str);
    let plan_edits: [PlanEdit; 5] = [
        (
            |plan, _| plan.mode = RestartMode::TransactionalHandoff,
            "not a supervised exit",
        ),
        (|plan, _| plan.systemd_verified = None, "no systemd unit"),
        (
            |plan, _| plan.systemd_verified.as_mut().unwrap().launcher = None,
            "does not run x0x-launcher",
        ),
        (
            |plan, _| launcher(plan).trial.plan_anchor = None,
            "no --plan-anchor",
        ),
        (
            |plan, host| launcher(plan).trial.host_root = host.root.join("elsewhere"),
            "--host-root",
        ),
    ];
    for (edit, reason) in plan_edits {
        let mut edited = plan(&host);
        edit(&mut edited, &host);
        closed_by(
            evaluate(true, &edited, &host.cli, &FakeProbe::open(&host)),
            reason,
        );
    }

    type ProbeEdit = (fn(&mut FakeProbe, &Host), &'static str);
    let probe_edits: [ProbeEdit; 11] = [
        (
            |probe, _| probe.files = Err(io::Error::other("no systemd")),
            "did not report",
        ),
        (
            |probe, _| probe.files.as_mut().unwrap().need_daemon_reload = true,
            "daemon-reload",
        ),
        (
            |probe, _| {
                probe
                    .files
                    .as_mut()
                    .unwrap()
                    .dropins
                    .pop()
                    .map(drop)
                    .unwrap_or(())
            },
            "launcher drop-in",
        ),
        (
            |probe, host| {
                let files = probe.files.as_mut().unwrap();
                files.dropins.push(host.root.join("x").join(DROPIN_NAME));
            },
            "launcher drop-in",
        ),
        (
            |_, host| std::fs::write(&host.dropin, "[Service]\nExecStart=/usr/bin/x0xd\n").unwrap(),
            "launcher drop-in",
        ),
        (
            |_, host| {
                let real = host.root.join("real.conf");
                std::fs::rename(&host.dropin, &real).unwrap();
                std::os::unix::fs::symlink(&real, &host.dropin).unwrap();
            },
            "launcher drop-in",
        ),
        (
            |probe, _| probe.anchor = b"{}".to_vec(),
            "fails the launcher's checks",
        ),
        (
            |probe, host| {
                probe.anchor = anchor_json(
                    &host.root.join("other"),
                    &host.cli,
                    &[("alice", &host.root)],
                )
            },
            "another install",
        ),
        (
            |probe, host| {
                probe.anchor = anchor_json(
                    &host.daemon,
                    &host.cli,
                    &[("alice", &host.root), ("bob", &host.root.join("bob"))],
                )
            },
            "more than one participant",
        ),
        (
            |probe, host| {
                probe.anchor = anchor_json(&host.daemon, &host.cli, &[("bob", &host.root)])
            },
            "not this instance",
        ),
        (
            |probe, _| probe.capabilities = Ok(Vec::new()),
            "does not answer trial-v1",
        ),
    ];
    for (edit, reason) in probe_edits {
        let host = self::host();
        let mut probe = FakeProbe::open(&host);
        edit(&mut probe, &host);
        closed_by(evaluate(true, &plan(&host), &host.cli, &probe), reason);
    }
    // Near misses of the capability name are not it.
    for near in [
        &["trial-v10"][..],
        &["xtrial-v1"],
        &["trial-v1 extra"],
        &["TRIAL-V1"],
    ] {
        let host = self::host();
        let mut probe = FakeProbe::open(&host);
        probe.capabilities = Ok(near.iter().map(|c| c.to_string()).collect());
        closed_by(
            evaluate(true, &plan(&host), &host.cli, &probe),
            "does not answer trial-v1",
        );
    }
    let host = self::host();
    let mut probe = FakeProbe::open(&host);
    probe.capabilities = Err(io::Error::other("exit 64"));
    closed_by(
        evaluate(true, &plan(&host), &host.cli, &probe),
        "did not answer",
    );
}

/// In this build the gate is closed for every apply and the decision is
/// remembered for diagnostics; no launcher is run and nothing is written.
#[test]
fn this_build_never_opens_the_gate() {
    const { assert!(!launcher_contract::LAUNCHER_ENABLED) };
    let host = host();
    let release = Release {
        previous_version: "1.0.0".into(),
        candidate_version: "2.0.0".into(),
        manifest_sha256: [0; 32],
    };
    assert!(gate_for_apply(&plan(&host), Some(&host.cli), release).is_none());
    let last = last_gate().expect("remembered");
    assert!(!last.open);
    assert!(last.reason.contains("dormant"), "{}", last.reason);
    assert_eq!(std::fs::read_dir(&host.root).unwrap().count(), 3);
}

#[test]
fn unit_files_need_an_explicit_reload_answer() {
    let files =
        parse_unit_files("NeedDaemonReload=no\nDropInPaths=/a/10.conf /b/30-x0x-launcher.conf\n")
            .unwrap();
    assert!(!files.need_daemon_reload);
    assert_eq!(files.dropins.len(), 2);
    assert!(
        parse_unit_files("NeedDaemonReload=yes\n")
            .unwrap()
            .need_daemon_reload
    );
    assert!(parse_unit_files("DropInPaths=\n").is_err());
}

/// `--capabilities` must exit 0 within its bound; its lines are the answer.
#[test]
fn capabilities_come_from_a_bounded_run() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let script = |name: &str, body: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    };
    let short = std::time::Duration::from_secs(5);
    let answers = script("answers", r#"[ "$1" = --capabilities ] && echo trial-v1"#);
    assert_eq!(run_capabilities(&answers, short).unwrap(), vec!["trial-v1"]);
    let dormant = script("dormant", "exit 0");
    assert!(run_capabilities(&dormant, short).unwrap().is_empty());
    let old = script("old", "echo trial-v1; exit 64");
    assert!(run_capabilities(&old, short).is_err());
    let hangs = script("hangs", "exec sleep 30");
    let started = std::time::Instant::now();
    let error = run_capabilities(&hangs, std::time::Duration::from_millis(200)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

// ------------------------------------------------------ the transaction

struct Install {
    _dir: tempfile::TempDir,
    root: PathBuf,
    daemon: PathBuf,
    cli: PathBuf,
    scratch: PathBuf,
}

fn install() -> Install {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let scratch = root.join("scratch");
    std::fs::create_dir(&scratch).unwrap();
    let daemon = root.join("x0xd");
    let cli = root.join("x0x");
    std::fs::write(&daemon, b"old-daemon").unwrap();
    std::fs::write(&cli, b"old-cli").unwrap();
    std::fs::write(scratch.join("daemon"), b"new-daemon").unwrap();
    std::fs::write(scratch.join("cli"), b"new-cli").unwrap();
    std::fs::write(
        root.join(plan_binding::TEST_ANCHOR_NAME),
        anchor_json(&daemon, &cli, &[("alice", &root)]),
    )
    .unwrap();
    std::fs::set_permissions(
        root.join(plan_binding::TEST_ANCHOR_NAME),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    Install {
        _dir: dir,
        root,
        daemon,
        cli,
        scratch,
    }
}

fn read_test_anchor(path: &Path) -> io::Result<plan_binding::Anchored> {
    Ok(plan_binding::read_test_anchor(path))
}

fn transaction(install: &Install) -> Transaction {
    let daemon = install.daemon.clone();
    Transaction {
        transaction_id: uuid::Uuid::new_v4().to_string(),
        anchor_path: install.root.join(plan_binding::TEST_ANCHOR_NAME),
        data_root: install.root.clone(),
        release: Release {
            previous_version: "1.0.0".into(),
            candidate_version: "2.0.0".into(),
            manifest_sha256: [9; 32],
        },
        participant: Participant {
            instance_id: "alice".into(),
            executable: daemon.clone(),
            data_root: install.root.clone(),
            identity_root: install.root.clone(),
            argv: vec![daemon.to_string_lossy().into_owned()],
            cwd: install.root.clone(),
            env: BTreeMap::new(),
            restart: RestartBinding {
                mode: RestartOwner::SupervisedExit,
                supervised_exit_code: Some(0),
                supervision_signal: None,
                launchd_verified: None,
                systemd_verified: None,
                launcher: None,
            },
            old_pid: None,
            process_start: None,
            boot_id: "boot".into(),
            was_running: false,
        },
        read_anchor: read_test_anchor,
    }
}

fn locks(install: &Install) -> (Option<InstallLock>, InstallLock) {
    (
        Some(super::super::acquire_install_lock(&install.cli).unwrap()),
        super::super::acquire_install_lock(&install.daemon).unwrap(),
    )
}

fn journal_record(root: &Path) -> journal::JournalRecord {
    let journal::RecordRead::Journal(record) = journal::read_boot_records(root).journal else {
        panic!("no journal");
    };
    *record
}

fn run(
    install: &Install,
    transaction: Transaction,
) -> Result<super::super::apply::Swapped, UpgradeError> {
    let (cli_lock, daemon_lock) = locks(install);
    transaction.run(
        cli_lock,
        daemon_lock,
        &Upgrader::new(install.daemon.clone(), semver::Version::new(1, 0, 0)),
        &install.scratch.join("daemon"),
        Some((
            Upgrader::new(install.cli.clone(), semver::Version::new(1, 0, 0)),
            install.scratch.join("cli"),
        )),
    )
}

/// An open gate's transaction: durable backups, the journal and its
/// binding, then the daemon swap and its record, then the CLI swap and its
/// record (SwappedCli). The restart owner gets the host lock.
#[test]
fn the_transaction_swaps_the_daemon_then_the_cli_under_its_records() {
    let install = install();
    STEPS.with(|steps| steps.borrow_mut().clear());
    let swapped = run(&install, transaction(&install)).unwrap();
    let super::super::apply::Swapped::Done { swapped, locks, .. } = swapped else {
        panic!("rolled back");
    };
    assert_eq!(
        STEPS.with(|steps| steps.borrow().clone()),
        vec![
            "directory synced",
            "directory synced",
            "prepared",
            "directory synced",
            "daemon swapped",
            "directory synced",
            "cli swapped"
        ]
    );
    let record = journal_record(&install.root);
    assert_eq!(record.phase, Phase::SwappedCli);
    assert!(record.daemon_progress.swapped && record.cli_progress.swapped);
    assert_eq!(std::fs::read(&install.daemon).unwrap(), b"new-daemon");
    assert_eq!(std::fs::read(&install.cli).unwrap(), b"new-cli");
    assert_eq!(
        std::fs::read(install.daemon.with_extension("backup")).unwrap(),
        b"old-daemon"
    );
    assert_eq!(
        std::fs::read(install.cli.with_extension("backup")).unwrap(),
        b"old-cli"
    );
    assert!(install
        .root
        .join(plan_binding::binding_file_name(&record.transaction_id))
        .is_file());
    assert_eq!(swapped.len(), 2);
    // The host lock travels to the restart owner.
    let held = std::fs::OpenOptions::new()
        .write(true)
        .open(install.root.join("x0xd.upgrade.lock"))
        .unwrap();
    assert!(matches!(
        held.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    drop(locks);
    assert!(held.try_lock().is_ok());
}

/// A failed CLI swap restores the daemon from its backup (the backup
/// stays) and supersedes the journal: the launcher then passes through to
/// the previous pair and the next stage replaces the journal. Red: return
/// the error without the restore and the Superseded write.
#[test]
fn a_failed_swap_restores_the_daemon_and_supersedes_the_journal() {
    let install = install();
    FAIL_INSTALL.with(|fail| *fail.borrow_mut() = Some(install.cli.clone()));
    let error = run(&install, transaction(&install)).err().expect("failed");
    FAIL_INSTALL.with(|fail| *fail.borrow_mut() = None);
    assert!(error.to_string().contains("superseded"), "{error}");
    assert_eq!(std::fs::read(&install.daemon).unwrap(), b"old-daemon");
    assert_eq!(std::fs::read(&install.cli).unwrap(), b"old-cli");
    assert_eq!(
        std::fs::read(install.daemon.with_extension("backup")).unwrap(),
        b"old-daemon"
    );
    let record = journal_record(&install.root);
    assert_eq!(record.phase, Phase::Superseded);
    assert!(record.daemon_progress.restored && !record.cli_progress.restored);
    // A settled journal does not block the next apply.
    assert!(!journal::read_boot_records(&install.root).blocks_apply());
}

/// The anchor is read while the data root's stage lock is held (#2012):
/// the installer takes the same lock around its anchor change. Red: read
/// the anchor before the stage lock.
#[test]
fn the_anchor_is_read_under_the_stage_lock() {
    let install = install();
    let mut transaction = transaction(&install);
    fn checked_read(path: &Path) -> io::Result<plan_binding::Anchored> {
        let lock = std::fs::OpenOptions::new()
            .write(true)
            .open(path.with_file_name(prepare::STAGE_LOCK_NAME))?;
        assert!(
            matches!(lock.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
            "the stage lock must be held while the anchor is read"
        );
        Ok(plan_binding::read_test_anchor(path))
    }
    transaction.read_anchor = checked_read;
    assert!(run(&install, transaction).is_ok());
}

/// An anchor that no longer names the plan's install (an installer change
/// before the stage lock) refuses the stage: nothing is swapped and no
/// journal is written.
#[test]
fn an_anchor_for_another_install_refuses_before_any_swap() {
    let install = install();
    std::fs::write(
        install.root.join(plan_binding::TEST_ANCHOR_NAME),
        anchor_json(&install.daemon, &install.cli, &[("bob", &install.root)]),
    )
    .unwrap();
    let error = run(&install, transaction(&install)).err().expect("refused");
    assert!(
        error.to_string().contains("launcher plan refused"),
        "{error}"
    );
    assert_eq!(std::fs::read(&install.daemon).unwrap(), b"old-daemon");
    assert!(matches!(
        journal::read_boot_records(&install.root).journal,
        journal::RecordRead::Missing
    ));
}

/// The plan names the CLI: an install without a sibling CLI is refused
/// before any change.
#[test]
fn the_transaction_needs_the_sibling_cli() {
    let install = install();
    let (_, daemon_lock) = locks(&install);
    let error = transaction(&install)
        .run(
            None,
            daemon_lock,
            &Upgrader::new(install.daemon.clone(), semver::Version::new(1, 0, 0)),
            &install.scratch.join("daemon"),
            None,
        )
        .err()
        .expect("refused");
    assert!(error.to_string().contains("sibling x0x CLI"), "{error}");
    assert!(!install.daemon.with_extension("backup").exists());
}

/// A refused restart restored the binaries: the held locks supersede the
/// producer's journal (`HeldInstallLocks::binaries_restored`).
#[test]
fn a_refused_restart_supersedes_the_journal_after_the_restore() {
    let install = install();
    let super::super::apply::Swapped::Done {
        swapped, mut locks, ..
    } = run(&install, transaction(&install)).unwrap()
    else {
        panic!("rolled back");
    };
    super::super::restore_swapped_binaries(&swapped).unwrap();
    locks.binaries_restored();
    assert_eq!(journal_record(&install.root).phase, Phase::Superseded);
}
