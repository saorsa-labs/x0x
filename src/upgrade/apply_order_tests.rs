#![cfg(test)]
//! The live apply path's pair order and lock custody (#2012, PR 3 part A).
use super::*;
use std::sync::{LazyLock, Mutex};
use tempfile::TempDir;

static SWAPS: LazyLock<Mutex<Vec<PathBuf>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// The swap seam: each target, in the order `swap_pair` starts its swap.
pub(super) fn record_swap(target: &Path) {
    SWAPS.lock().unwrap().push(target.to_path_buf());
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
    assert!(error.to_string().contains("companion lock"), "{error}");
    assert_eq!(std::fs::read(&pair.daemon).unwrap(), b"old-daemon");
    assert!(swaps_under(pair.root.path()).is_empty());
    assert!(!pair.marker().exists());
}

/// A companion that fails validation fails the apply before any lock or
/// swap. Red: the pre-#2012 warn-and-skip.
#[tokio::test]
async fn a_companion_that_fails_validation_fails_before_any_swap() {
    let pair = Pair::new();
    let error = pair
        .apply(
            pair.companion(semver::Version::new(3, 0, 0)),
            pair.continuation(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("companion refused"), "{error}");
    assert_eq!(std::fs::read(&pair.daemon).unwrap(), b"old-daemon");
    assert!(swaps_under(pair.root.path()).is_empty());
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
