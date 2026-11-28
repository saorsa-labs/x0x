#![cfg(test)]
//! The live apply path's pair order and lock custody (#2012, PR 3 part A).
use super::*;
use std::sync::{LazyLock, Mutex};
use tempfile::TempDir;

static SWAPS: LazyLock<Mutex<Vec<PathBuf>>> = LazyLock::new(|| Mutex::new(Vec::new()));
type SwapHook = Box<dyn FnOnce() + Send>;
static SWAP_HOOKS: LazyLock<Mutex<std::collections::HashMap<PathBuf, SwapHook>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

/// The swap seam: each target, in the order `swap_pair` starts its swap,
/// and a hook a test may run just before that target's swap.
pub(super) fn record_swap(target: &Path) {
    SWAPS.lock().unwrap().push(target.to_path_buf());
    let hook = SWAP_HOOKS.lock().unwrap().remove(target);
    if let Some(hook) = hook {
        hook();
    }
}

fn swaps_under(root: &Path) -> Vec<PathBuf> {
    SWAPS
        .lock()
        .unwrap()
        .iter()
        .filter(|path| path.starts_with(root))
        .cloned()
        .collect()
}

struct Pair {
    root: TempDir,
    daemon: PathBuf,
    cli: PathBuf,
    scratch: PathBuf,
}

impl Pair {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let scratch = root.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let daemon = root.path().join("x0xd");
        let cli = root.path().join("x0x");
        std::fs::write(&daemon, b"old-daemon").unwrap();
        std::fs::write(&cli, b"old-cli").unwrap();
        std::fs::write(scratch.join("daemon"), b"new-daemon").unwrap();
        std::fs::write(scratch.join("cli"), b"new-cli").unwrap();
        Self {
            root,
            daemon,
            cli,
            scratch,
        }
    }

    fn companion(&self, cli_version: semver::Version) -> Option<(Upgrader, PathBuf)> {
        Some((
            Upgrader::new(self.cli.clone(), cli_version),
            self.scratch.join("cli"),
        ))
    }

    async fn apply(
        &self,
        companion: Option<(Upgrader, PathBuf)>,
        on_success: Option<RestartContinuation>,
    ) -> Result<UpgradeResult, UpgradeError> {
        apply_replacements_offloaded(
            Upgrader::new(self.daemon.clone(), semver::Version::new(1, 0, 0)),
            self.scratch.join("daemon"),
            semver::Version::new(2, 0, 0),
            companion,
            TempDirGuard {
                path: self.scratch.clone(),
            },
            on_success,
            None,
        )
        .await
    }

    /// A second scratch directory with fresh candidates, for a second apply.
    fn second_scratch(&self) -> PathBuf {
        let scratch = self.root.path().join("scratch-2");
        std::fs::create_dir(&scratch).unwrap();
        std::fs::write(scratch.join("daemon"), b"newer-daemon").unwrap();
        std::fs::write(scratch.join("cli"), b"newer-cli").unwrap();
        scratch
    }

    fn marker(&self) -> PathBuf {
        self.root.path().join("restart-continuation")
    }

    fn continuation(&self) -> Option<RestartContinuation> {
        let marker = self.marker();
        Some(Box::new(move |_, _| {
            std::fs::write(marker, b"restart").unwrap()
        }))
    }

    fn lock_is_held(&self, target: &Path) -> bool {
        let mut name = target.file_name().unwrap().to_os_string();
        name.push(".upgrade.lock");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(target.with_file_name(name))
            .unwrap();
        matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock))
    }
}

/// The daemon is swapped before the CLI, the order the host journal
/// records (SwappedDaemon, then SwappedCli). Red: swap the companion first.
#[tokio::test]
async fn the_daemon_is_swapped_before_the_cli() {
    let pair = Pair::new();
    let result = pair
        .apply(
            pair.companion(semver::Version::new(1, 0, 0)),
            pair.continuation(),
        )
        .await
        .unwrap();
    assert!(matches!(result, UpgradeResult::Success { .. }));
    assert_eq!(
        swaps_under(pair.root.path()),
        vec![pair.daemon.clone(), pair.cli.clone()]
    );
    assert_eq!(std::fs::read(&pair.daemon).unwrap(), b"new-daemon");
    assert_eq!(std::fs::read(&pair.cli).unwrap(), b"new-cli");
    assert!(pair.marker().exists());
}

/// A companion whose swap fails restores the daemon this apply swapped and
/// fails the apply: no restart, the previous pair installed. Red: the
/// pre-#2012 warn-and-continue.
#[tokio::test]
async fn a_failed_companion_swap_restores_the_daemon_and_fails_the_apply() {
    let pair = Pair::new();
    // The CLI backup cannot be written: a directory sits at its path.
    std::fs::create_dir(pair.cli.with_extension("backup")).unwrap();
    let error = pair
        .apply(
            pair.companion(semver::Version::new(1, 0, 0)),
            pair.continuation(),
        )
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("daemon binary was restored"),
        "{error}"
    );
    assert_eq!(std::fs::read(&pair.daemon).unwrap(), b"old-daemon");
    assert_eq!(std::fs::read(&pair.cli).unwrap(), b"old-cli");
    assert!(!pair.marker().exists(), "a failed apply must not restart");
}

/// A companion that cannot be locked fails the apply before any byte
/// changes. Red: the pre-#2012 warn-and-skip, which swapped the daemon alone.
#[tokio::test]
async fn a_companion_that_cannot_be_locked_fails_before_any_swap() {
    let pair = Pair::new();
    std::fs::create_dir(pair.root.path().join("x0x.upgrade.lock")).unwrap();
    let error = pair
        .apply(
            pair.companion(semver::Version::new(1, 0, 0)),
            pair.continuation(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().starts_with(COMPANION_FAILURE), "{error}");
    assert!(
        error.to_string().contains("install lock cannot be taken"),
        "{error}"
    );
    assert_eq!(std::fs::read(&pair.daemon).unwrap(), b"old-daemon");
    assert!(swaps_under(pair.root.path()).is_empty());
    assert!(!pair.marker().exists());
}

/// The immediate restart owner runs with both install locks held. Red:
/// drop the locks before the continuation.
#[tokio::test]
async fn the_restart_owner_runs_with_both_install_locks_held() {
    let pair = Pair::new();
    let (daemon, cli) = (pair.daemon.clone(), pair.cli.clone());
    let held = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&held);
    let probe = Pair {
        root: TempDir::new().unwrap(),
        daemon: daemon.clone(),
        cli: cli.clone(),
        scratch: PathBuf::new(),
    };
    let on_success: Option<RestartContinuation> = Some(Box::new(move |_, _locks| {
        *seen.lock().unwrap() = Some((probe.lock_is_held(&daemon), probe.lock_is_held(&cli)));
    }));
    pair.apply(pair.companion(semver::Version::new(1, 0, 0)), on_success)
        .await
        .unwrap();
    assert_eq!(*held.lock().unwrap(), Some((true, true)));
    assert!(
        !pair.lock_is_held(&pair.daemon),
        "released after the owner returns"
    );
}

/// The HTTP deferred restart keeps both install locks through its delay
/// and its restart (#2012). Red: the pre-#2012 worker, which released them
/// when it returned, before the delayed restart.
#[tokio::test]
async fn the_http_deferred_restart_keeps_the_install_locks_until_it_runs() {
    let pair = Pair::new();
    let data_root = pair.root.path().join("data");
    std::fs::create_dir(&data_root).unwrap();
    let plan = restart::RestartPlan {
        mode: restart::RestartMode::SupervisedExit,
        supervised_exit_code: Some(0),
        supervision_signal: None,
        executable: pair.daemon.clone(),
        argv: vec!["x0xd".into()],
        cwd: pair.root.path().to_path_buf(),
        data_root,
        api_addr: "127.0.0.1:9".parse().unwrap(),
        launchd_verified: None,
        systemd_verified: None,
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let (daemon, cli) = (pair.daemon.clone(), pair.cli.clone());
    let probe = Pair {
        root: TempDir::new().unwrap(),
        daemon: daemon.clone(),
        cli: cli.clone(),
        scratch: PathBuf::new(),
    };
    let tx = Mutex::new(tx);
    let _hook = http_deferred_restart_seam::install(
        pair.daemon.clone(),
        Arc::new(move |_, _| {
            let _ = tx
                .lock()
                .unwrap()
                .send((probe.lock_is_held(&daemon), probe.lock_is_held(&cli)));
        }),
    );
    let owner = arm_http_deferred_restart_owner(
        "x0xd".into(),
        true,
        RestartContext::default(),
        plan,
        "2.0.0".into(),
        None,
    )
    .unwrap();
    pair.apply(pair.companion(semver::Version::new(1, 0, 0)), Some(owner))
        .await
        .unwrap();
    // The worker has returned; the deferred owner has not run yet.
    assert!(pair.lock_is_held(&pair.daemon) && pair.lock_is_held(&pair.cli));
    let seen = tokio::task::spawn_blocking(move || {
        rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap()
    })
    .await
    .unwrap();
    assert_eq!(
        seen,
        (true, true),
        "the locks are held while the restart runs"
    );
}

/// A companion swap that rolls itself back (its replace failed and its
/// own backup was put back) is a failure, not a success: the daemon is
/// restored and the apply fails. Red: treat `RolledBack` as success.
#[tokio::test]
async fn a_companion_swap_that_rolls_back_fails_the_apply() {
    let pair = Pair::new();
    // A directory as the CLI candidate: the rename over the file fails.
    std::fs::remove_file(pair.scratch.join("cli")).unwrap();
    std::fs::create_dir(pair.scratch.join("cli")).unwrap();
    let error = pair
        .apply(
            pair.companion(semver::Version::new(1, 0, 0)),
            pair.continuation(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().starts_with(COMPANION_FAILURE), "{error}");
    assert!(
        error.to_string().contains("daemon binary was restored"),
        "{error}"
    );
    assert_eq!(std::fs::read(&pair.daemon).unwrap(), b"old-daemon");
    assert_eq!(std::fs::read(&pair.cli).unwrap(), b"old-cli");
    assert!(!pair.marker().exists());
}

/// A companion failure when this apply swapped no daemon (it already held
/// the candidate) says that nothing was replaced. Red: report a restore.
#[tokio::test]
async fn a_companion_failure_over_an_unswapped_daemon_replaces_nothing() {
    let pair = Pair::new();
    std::fs::write(&pair.daemon, b"new-daemon").unwrap();
    std::fs::create_dir(pair.cli.with_extension("backup")).unwrap();
    let error = pair
        .apply(
            pair.companion(semver::Version::new(1, 0, 0)),
            pair.continuation(),
        )
        .await
        .unwrap_err();
    assert!(
        error.to_string().ends_with("nothing was replaced"),
        "{error}"
    );
    assert_eq!(std::fs::read(&pair.cli).unwrap(), b"old-cli");
}

/// A daemon that cannot be restored after a companion failure is named as
/// a mixed pair that needs manual recovery. Red: report it as restored.
#[tokio::test]
async fn a_daemon_that_cannot_be_restored_is_named_a_mixed_pair() {
    let pair = Pair::new();
    std::fs::create_dir(pair.cli.with_extension("backup")).unwrap();
    let daemon_backup = pair.daemon.with_extension("backup");
    SWAP_HOOKS.lock().unwrap().insert(
        pair.cli.clone(),
        Box::new(move || std::fs::remove_file(daemon_backup).unwrap()),
    );
    let error = pair
        .apply(
            pair.companion(semver::Version::new(1, 0, 0)),
            pair.continuation(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("mixed"), "{error}");
    assert!(error.to_string().contains("cannot be restored"), "{error}");
    assert_eq!(std::fs::read(&pair.daemon).unwrap(), b"new-daemon");
    assert!(!pair.marker().exists());
}

/// #2012 review: while a restart owner in this process holds the install
/// locks (here parked, as the HTTP deferred owner is during its delay and
/// flush), a second apply in the same process fails at once with
/// `RESTART_IN_PROGRESS` instead of waiting for the locks, so it cannot
/// hold up the restart's shutdown drain. Red: the blocking lock wait of
/// baacd676 (the second apply waits until the owner releases).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_in_process_lock_wait_fails_fast_while_the_restart_owner_holds_the_locks() {
    let pair = Pair::new();
    let (parked_tx, parked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let owner: Option<RestartContinuation> = Some(Box::new(move |_, locks| {
        std::thread::spawn(move || {
            let _locks = locks;
            parked_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(20));
        });
    }));
    pair.apply(pair.companion(semver::Version::new(1, 0, 0)), owner)
        .await
        .unwrap();
    parked_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let scratch = pair.second_scratch();
    let second = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        apply_replacements_offloaded(
            Upgrader::new(pair.daemon.clone(), semver::Version::new(1, 0, 0)),
            scratch.join("daemon"),
            semver::Version::new(3, 0, 0),
            Some((
                Upgrader::new(pair.cli.clone(), semver::Version::new(1, 0, 0)),
                scratch.join("cli"),
            )),
            TempDirGuard {
                path: scratch.clone(),
            },
            None,
            None,
        ),
    )
    .await
    .expect("an in-process lock wait must not block while the restart owner holds the locks");
    let error = second.unwrap_err();
    assert!(super::super::is_restart_in_progress(&error), "{error}");
    assert_eq!(std::fs::read(&pair.daemon).unwrap(), b"new-daemon");
    release_tx.send(()).unwrap();
}

/// #2012 review: dropping the restart owner's mark (a refused or abandoned
/// restart) lets a later in-process wait take the lock. Red: a `Drop` that
/// leaves the mark.
#[test]
fn a_released_restart_owner_mark_lets_a_later_wait_take_the_lock() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("x0xd");
    std::fs::write(&target, b"daemon").unwrap();
    let mark = super::super::RestartOwnerMark::new(&[&target]);
    let refused = super::super::acquire_install_lock(&target).err().unwrap();
    assert!(super::super::is_restart_in_progress(&refused), "{refused}");
    drop(mark);
    assert!(super::super::acquire_install_lock(&target).is_ok());
}

/// #2012 review: a wait that began before the mark (another holder had the
/// lock) fails at its next poll once the restart owner's mark appears.
/// Red: check the mark only once, before the wait.
#[test]
fn a_wait_that_began_before_the_mark_fails_at_its_next_poll() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("x0xd");
    std::fs::write(&target, b"daemon").unwrap();
    let holder = super::super::acquire_install_lock(&target).unwrap();
    let waiting = target.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let _ = tx.send(super::super::acquire_install_lock(&waiting).map(drop));
    });
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(rx.try_recv().is_err(), "still waiting on the holder");
    let mark = super::super::RestartOwnerMark::new(&[&target]);
    let result = rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("the waiter must stop at its next poll");
    let error = result.expect_err("refused");
    assert!(super::super::is_restart_in_progress(&error), "{error}");
    waiter.join().unwrap();
    drop(mark);
    drop(holder);
}

/// #2012 review: a companion failure writes the record (with the mixed
/// flag when the daemon could not be restored); any other error does not.
/// The record then refuses the same release until it is removed; a
/// successful apply's continuation removes it before the restart. Red:
/// recording off, or the success path not clearing.
#[test]
fn a_companion_failure_is_recorded_and_backs_off_until_cleared() {
    use super::super::companion_failure::{self as record, Read};
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let other = note_companion_failure(root, "9.0.0", UpgradeError::Other("network".into()));
    assert_eq!(other.to_string(), "network");
    assert_eq!(record::read(root), Read::Missing);
    let failure = companion_failure(Path::new("/opt/x0x/x0x"), "denied", "nothing was replaced");
    note_companion_failure(root, "9.0.0", failure);
    let Read::Record(written) = record::read(root) else {
        panic!("recorded");
    };
    assert_eq!((written.version.as_str(), written.failures), ("9.0.0", 1));
    assert!(!written.pair_mixed);
    let refused = refuse_backed_off(root, "9.0.0").unwrap_err();
    assert!(
        refused.to_string().starts_with(record::BACKOFF),
        "{refused}"
    );
    assert!(refused.to_string().contains(record::RECORD), "{refused}");
    assert!(refuse_backed_off(root, "9.0.1").is_ok(), "a newer release");
    record::clear(root);
    assert_eq!(record::read(root), Read::Missing);
    assert!(refuse_backed_off(root, "9.0.0").is_ok());
    let mixed = companion_failure(
        Path::new("/opt/x0x/x0x"),
        "denied",
        &format!(
            "the daemon binary cannot be restored (gone); {}",
            record::MIXED
        ),
    );
    note_companion_failure(root, "9.0.0", mixed);
    assert!(matches!(record::read(root), Read::Record(r) if r.pair_mixed));
}

#[tokio::test]
async fn apply_upgrade_from_manifest_refuses_backed_off_release() {
    use super::super::companion_failure::{self as record, Read};
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let target = root.join("x0xd");
    std::fs::write(&target, b"old-daemon").unwrap();
    let version = "99.9.9";
    let failure = companion_failure(Path::new("/opt/x0x/x0x"), "denied", "nothing was replaced");
    note_companion_failure(root, version, failure);
    assert!(matches!(record::read(root), Read::Record(_)));

    let target_triple = current_platform_target().expect("supported test platform");
    let manifest = ReleaseManifest {
        schema_version: super::super::manifest::SCHEMA_VERSION,
        version: version.to_string(),
        channel: "stable".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        assets: vec![super::super::manifest::PlatformAsset {
            target: target_triple.to_string(),
            archive_url: "https://example.invalid/x0x.tar.gz".to_string(),
            archive_sha256: [0x11; 32],
            signature_url: "https://example.invalid/x0x.tar.gz.sig".to_string(),
        }],
        skill_url: "https://example.invalid/SKILL.md".to_string(),
        skill_sha256: [0x22; 32],
    };

    let upgrader = AutoApplyUpgrader::new("x0xd")
        .with_restart_on_success(false)
        .with_restart_context(RestartContext {
            data_dir: Some(root.to_path_buf()),
            api_addr: None,
            shutdown: None,
        });
    let err = upgrader
        .apply_upgrade_from_manifest(&manifest)
        .await
        .expect_err("backed-off release must be refused by apply_upgrade_from_manifest");
    assert!(
        err.to_string().starts_with(record::BACKOFF),
        "expected companion backoff refusal, got: {err}"
    );
}

#[tokio::test]
async fn no_restart_success_clears_companion_failure_record_under_locks() {
    use super::super::companion_failure::{self as record, Read};
    let pair = Pair::new();
    let root = pair.root.path();
    let failure = companion_failure(&pair.cli, "denied", "nothing was replaced");
    note_companion_failure(root, "2.0.0", failure);
    assert!(matches!(record::read(root), Read::Record(_)));

    let result = apply_replacements_with_producer(
        Upgrader::new(pair.daemon.clone(), semver::Version::new(1, 0, 0)),
        pair.scratch.join("daemon"),
        semver::Version::new(2, 0, 0),
        pair.companion(semver::Version::new(1, 0, 0)),
        TempDirGuard {
            path: pair.scratch.clone(),
        },
        None,
        None,
        None,
        None,
        Some(root.to_path_buf()),
        #[cfg(unix)]
        None,
    )
    .await
    .expect("apply without restart owner succeeds");
    assert!(matches!(result, UpgradeResult::Success { .. }));
    assert_eq!(
        record::read(root),
        Read::Missing,
        "companion failure record must be cleared on no-restart success"
    );
}
