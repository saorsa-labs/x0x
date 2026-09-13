//! Explicit single-instance guard on the daemon data directory (issue #601).
//!
//! Before this module, the only thing preventing two `x0xd` processes on one
//! data directory was SQLite's `PRAGMA locking_mode = EXCLUSIVE` on
//! `history.db` (`src/history/store.rs`). That guard was:
//!
//! - **implicit** — the second process died with
//!   `failed to create agent / history initialization failed`, which reads as
//!   a history subsystem fault rather than "another daemon owns this data
//!   dir" (issue #493 shows operators hitting exactly that confusion), and
//! - **conditional on `[history] enabled`** — verified live during the #601
//!   investigation: with `history.enabled = false`, two daemons coexist fully
//!   on one data directory (and one identity directory), both signing as the
//!   SAME agent identity with no coordination and no warning.
//!
//! The replacement is an advisory exclusive lock on
//! `<data_dir>/instance.lock`, taken in
//! [`crate::server::serve_with_options`] immediately after the data dir is
//! created — before the startup update check, the API listener, identity
//! load/generation, or any other subsystem touches the directory — and held
//! by the spawned supervisor task until it has finished draining (#645):
//! the guard must outlive [`crate::server::ServerHandle`]'s `Drop`, or an
//! embedded caller that drops and immediately re-serves the same data dir
//! briefly runs two servers on it. A configured `identity_dir` shared
//! across two different data dirs gets the same guard (one
//! `instance.lock` inside the identity dir): two daemons loading the same
//! machine/agent keys would both sign as one agent — the #601 hazard, one
//! directory up. The lock is deliberately independent of the history
//! subsystem.
//!
//! Crash safety: the lock rides the open file description (`flock` on Unix, a
//! write-share-denying open on Windows), so the kernel releases it when the
//! process exits — even on crash or `kill -9`. A leftover `instance.lock`
//! file never blocks the next start; the decision is made by the kernel-level
//! lock alone. The file's contents (the holder's pid) are diagnostics for the
//! *refused* daemon's error message, read best-effort.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Name of the lockfile inside a guarded directory (the data dir, or a
/// shared configured identity dir — #645).
pub(super) const INSTANCE_LOCK_FILE: &str = "instance.lock";

/// The held single-instance lock.
///
/// Keeps the underlying file open for the daemon's lifetime. The server
/// moves the guard into its spawned supervisor task (#645), so the lock is
/// released only after the server has fully drained — not when the
/// [`crate::server::ServerHandle`] is dropped. Process exit releases it
/// unconditionally.
pub struct InstanceLock {
    /// The locked file. Underscored: merely holding it open is the guard.
    _file: File,
}

impl fmt::Debug for InstanceLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstanceLock(<held>)")
    }
}

/// What an [`InstanceLock`] guards. Only the operator-facing refusal
/// wording changes; the mechanism (one `instance.lock` per guarded
/// directory) is identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockTarget {
    /// The daemon data directory (`<data_dir>/instance.lock`, issue #601).
    DataDir,
    /// A configured identity directory shared across data dirs (#645):
    /// `<identity_dir>/instance.lock`.
    IdentityDir,
}

impl LockTarget {
    /// How the guarded directory is named in the refusal message.
    fn noun(self) -> &'static str {
        match self {
            Self::DataDir => "data dir",
            Self::IdentityDir => "identity dir",
        }
    }

    /// How the operator is told to start the refused daemon elsewhere.
    fn start_elsewhere_advice(self) -> &'static str {
        match self {
            Self::DataDir => "start this daemon with a different --name / data_dir",
            Self::IdentityDir => "point this daemon at a different identity_dir",
        }
    }
}

/// Failure to establish the single-instance guard.
#[derive(Debug)]
pub enum InstanceLockError {
    /// The lockfile could not be created or opened (permissions, I/O error).
    Open {
        /// What the lock would have guarded.
        target: LockTarget,
        /// The guarded directory.
        dir: PathBuf,
        path: PathBuf,
        source: std::io::Error,
    },
    /// A live process already holds the lock — another daemon owns the
    /// guarded directory. `holder_pid` is read best-effort from the
    /// lockfile; it may be `None` (unreadable or unrecorded) without
    /// weakening the refusal, which the kernel-level lock alone decided.
    Held {
        /// What the lock guards.
        target: LockTarget,
        /// The guarded directory.
        dir: PathBuf,
        path: PathBuf,
        holder_pid: Option<u32>,
    },
}

impl fmt::Display for InstanceLockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open {
                target,
                dir,
                path,
                source,
            } => write!(
                f,
                "cannot open instance lock {} in {} {}: {source}",
                path.display(),
                target.noun(),
                dir.display()
            ),
            Self::Held {
                target,
                dir,
                path,
                holder_pid,
            } => {
                write!(
                    f,
                    "another x0xd instance owns {} {} (instance lock {}",
                    target.noun(),
                    dir.display(),
                    path.display()
                )?;
                match holder_pid {
                    Some(pid) => write!(
                        f,
                        " held by pid {pid}); stop it first (x0x stop or kill {pid}), or {}",
                        target.start_elsewhere_advice()
                    ),
                    None => write!(
                        f,
                        " is already held); stop the running daemon first (x0x stop), or {}",
                        target.start_elsewhere_advice()
                    ),
                }
            }
        }
    }
}

impl std::error::Error for InstanceLockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open { source, .. } => Some(source),
            Self::Held { .. } => None,
        }
    }
}

impl InstanceLock {
    /// Acquire the single-instance lock for `data_dir` (issue #601).
    ///
    /// The caller must have created `data_dir` (the daemon does this
    /// immediately before calling). On success the returned guard MUST be
    /// kept alive for as long as the daemon intends to own the directory;
    /// dropping it releases the lock. On contention the error names the data
    /// dir and, best-effort, the pid of the holder.
    pub fn acquire(data_dir: &Path) -> Result<Self, InstanceLockError> {
        Self::acquire_for(data_dir, LockTarget::DataDir)
    }

    /// Acquire the single-instance lock guarding a *configured* identity
    /// directory (#645). Same file and mechanism as [`InstanceLock::acquire`];
    /// only the refusal message differs — it must name the identity dir so
    /// the operator of the refused daemon is pointed at the right conflict,
    /// not at their (uncontended) data dir.
    pub fn acquire_identity(identity_dir: &Path) -> Result<Self, InstanceLockError> {
        Self::acquire_for(identity_dir, LockTarget::IdentityDir)
    }

    fn acquire_for(dir: &Path, target: LockTarget) -> Result<Self, InstanceLockError> {
        let path = dir.join(INSTANCE_LOCK_FILE);
        let file = open_lock_file(&path).map_err(|source| {
            // Only Windows maps an open failure to contention: there the
            // share-mode open IS the guard, so a refused second daemon
            // fails with ERROR_SHARING_VIOLATION on the existing lockfile.
            // Every other failure — on Unix, every failure, e.g. EACCES on
            // a root-owned lockfile left behind by a `sudo` run — is
            // genuine I/O: reporting it as `Held` would tell the operator
            // to kill a pid for a lockfile they merely cannot open (#645).
            if open_failure_means_contention(&source) {
                let holder_pid = read_holder_pid(&path);
                InstanceLockError::Held {
                    target,
                    dir: dir.to_path_buf(),
                    path: path.clone(),
                    holder_pid,
                }
            } else {
                InstanceLockError::Open {
                    target,
                    dir: dir.to_path_buf(),
                    path: path.clone(),
                    source,
                }
            }
        })?;

        // Unix: take the advisory exclusive lock now, non-blocking.
        let locked = try_lock_exclusive(&file).map_err(|source| InstanceLockError::Open {
            target,
            dir: dir.to_path_buf(),
            path: path.clone(),
            source,
        })?;
        if !locked {
            let holder_pid = read_holder_pid(&path);
            return Err(InstanceLockError::Held {
                target,
                dir: dir.to_path_buf(),
                path,
                holder_pid,
            });
        }

        Self::held(file, path)
    }

    /// Complete acquisition on an already-locked file: record the holder
    /// pid (best-effort diagnostics) and return the guard.
    fn held(mut file: File, path: PathBuf) -> Result<Self, InstanceLockError> {
        // Record our pid for the NEXT refused daemon's error message.
        // Best-effort: the guard is already effective, and a failure here
        // must not invent a new startup-failure class — only degrade the
        // refusal message to "unknown pid".
        let pid = std::process::id().to_string();
        let recorded = file
            .set_len(0)
            .and_then(|()| file.write_all(pid.as_bytes()))
            .and_then(|()| file.sync_all());
        if let Err(e) = recorded {
            tracing::warn!(
                lock = %path.display(),
                error = %e,
                "instance lock acquired but recording the holder pid failed; \
                 a refused second daemon will report an unknown pid"
            );
        }

        tracing::debug!(
            lock = %path.display(),
            pid = std::process::id(),
            "single-instance lock acquired"
        );
        Ok(InstanceLock { _file: file })
    }
}
/// Read the pid recorded by the current lock holder, best-effort.
fn read_holder_pid(path: &Path) -> Option<u32> {
    let mut text = String::new();
    File::open(path).ok()?.read_to_string(&mut text).ok()?;
    text.trim().parse::<u32>().ok()
}

#[cfg(unix)]
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

#[cfg(windows)]
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_SHARE_READ only: a refused second daemon can still READ the
    // lockfile (for the holder pid in its error message), but its own
    // write-access open fails with a sharing violation — the guard.
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

/// Whether an `open_lock_file` failure means "another live daemon holds the
/// lock" rather than a genuine I/O failure. Only Windows can answer yes:
/// there the share-mode open IS the guard and contention surfaces as
/// `ERROR_SHARING_VIOLATION` (32) on the existing lockfile.
#[cfg(windows)]
fn open_failure_means_contention(source: &std::io::Error) -> bool {
    const ERROR_SHARING_VIOLATION: i32 = 32;
    source.raw_os_error() == Some(ERROR_SHARING_VIOLATION)
}

/// Unix has no open-time contention (`flock` is taken separately in
/// [`try_lock_exclusive`]), so no open failure ever means "held".
#[cfg(not(windows))]
fn open_failure_means_contention(_source: &std::io::Error) -> bool {
    false
}

/// Take the exclusive lock non-blocking. `Ok(true)` = acquired,
/// `Ok(false)` = held by another live process, `Err` = lock syscall failure.
#[cfg(unix)]
fn try_lock_exclusive(file: &File) -> std::io::Result<bool> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: `flock` operates on our own open fd and never invalidates it;
    // LOCK_NB makes contention return EWOULDBLOCK instead of blocking
    // daemon startup indefinitely.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    if err.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(false);
    }
    Err(err)
}

#[cfg(windows)]
fn try_lock_exclusive(_file: &File) -> std::io::Result<bool> {
    // The share-mode(READ)-only open in `open_lock_file` is the guard:
    // reaching here means our open succeeded, so no other process holds a
    // write handle. A contending daemon fails inside `open_lock_file` and
    // is mapped to `Held` there.
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_is_refused_and_names_the_holder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = InstanceLock::acquire(dir.path()).expect("first acquire must succeed");

        // The lockfile records the holder's pid for the refusal message.
        let recorded = std::fs::read_to_string(dir.path().join(INSTANCE_LOCK_FILE))
            .expect("lockfile readable");
        assert_eq!(recorded.trim(), std::process::id().to_string());

        // A second acquire in the same process uses a separate open file
        // description, so flock contention applies exactly as it would for
        // a second daemon process.
        let err = InstanceLock::acquire(dir.path()).expect_err("second acquire must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("another x0xd instance owns data dir"),
            "refusal must lead with the ownership fact: {msg}"
        );
        assert!(
            msg.contains(dir.path().display().to_string().as_str()),
            "refusal must name the data dir: {msg}"
        );
        assert!(
            msg.contains(&format!("pid {}", std::process::id())),
            "refusal must name the holder pid: {msg}"
        );
        // The whole point of #601: this must read as a data-dir ownership
        // conflict, not a history subsystem fault.
        assert!(
            !msg.to_lowercase().contains("history"),
            "refusal must not look like a history error: {msg}"
        );
        drop(first);
    }

    #[test]
    fn lock_releases_on_drop_so_a_crashed_daemon_never_wedges_the_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = InstanceLock::acquire(dir.path()).expect("first acquire");
        drop(first);
        // Dropping the guard (handle dropped / process exit) releases the
        // lock: the very next start on the same dir must succeed — a stale
        // lockfile must never block a restart.
        let second = InstanceLock::acquire(dir.path()).expect("re-acquire after drop");
        drop(second);
    }

    /// The regression that motivated issue #601: with `history.enabled =
    /// false` there used to be NO guard, and two daemons coexisted on one
    /// data directory (both signing as the same agent identity). The guard
    /// must refuse the second daemon through the public serve seam BEFORE
    /// any subsystem initialises — here: while the lock is held by
    /// "another daemon", serve must fail with the ownership error and must
    /// not have created anything in the data dir beyond the lockfile.
    #[tokio::test]
    async fn serve_is_refused_on_an_owned_data_dir_even_with_history_disabled() {
        use crate::server::{serve_with_options, DaemonConfig, ServeOptions};

        let dir = tempfile::tempdir().expect("tempdir");
        // Simulate the running daemon: hold the instance lock ourselves.
        let holder = InstanceLock::acquire(dir.path()).expect("hold the lock as daemon A");

        let config = DaemonConfig {
            data_dir: dir.path().to_path_buf(),
            identity_dir: Some(dir.path().join("identity")),
            api_address: "127.0.0.1:0".parse().expect("loopback api address"),
            bind_address: "127.0.0.1:0".parse().expect("loopback quic address"),
            bootstrap_peers: Some(Vec::new()),
            network_id: Some("issue-601.single-instance".to_string()),
            ..DaemonConfig::default()
        };
        // The exact configuration the live reproduction used: history
        // disabled, so the old implicit SQLite guard did not exist.
        let mut config = config;
        config.history.enabled = false;

        let options = ServeOptions {
            skip_update_check: true,
            cli_no_port_mapping: true,
            cli_disable_peer_cache: true,
            ..ServeOptions::default()
        };
        let err = match serve_with_options(config, options).await {
            Err(err) => err,
            Ok(handle) => {
                let _ = handle.shutdown_and_wait().await;
                panic!("second daemon must be refused on an owned data dir");
            }
        };
        let msg = err.to_string();
        assert!(
            msg.contains("another x0xd instance owns data dir"),
            "serve refusal must carry the ownership error, got: {msg}"
        );
        assert!(
            msg.contains(&format!("pid {}", std::process::id())),
            "serve refusal must name the holder pid, got: {msg}"
        );
        assert!(
            !msg.to_lowercase().contains("history"),
            "must not surface as a history fault, got: {msg}"
        );

        // "Before any subsystem initialises": apart from the lockfile, the
        // data dir must be untouched — no identity, no api.port, no peers
        // cache, nothing.
        let entries: Vec<std::ffi::OsString> = std::fs::read_dir(dir.path())
            .expect("data dir readable")
            .map(|e| e.expect("dirent").file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from(INSTANCE_LOCK_FILE)],
            "refused daemon must leave the data dir untouched"
        );
        drop(holder);
    }

    // ---- #645 follow-ups from the #629 review ---------------------------

    use crate::server::{serve_with_options, DaemonConfig, ServeOptions};
    use std::path::{Path, PathBuf};

    /// Hermetic serve fixture: no bootstrap peers, no mDNS, loopback
    /// ephemeral ports, isolated gossip plane, history off (the #601
    /// reproduction shape — the guard must not depend on history).
    fn hermetic_serve_config(
        data_dir: &Path,
        identity_dir: Option<PathBuf>,
        plane: &str,
    ) -> DaemonConfig {
        let mut config = DaemonConfig {
            data_dir: data_dir.to_path_buf(),
            identity_dir,
            api_address: "127.0.0.1:0".parse().expect("loopback api address"),
            bind_address: "127.0.0.1:0".parse().expect("loopback quic address"),
            bootstrap_peers: Some(Vec::new()),
            network_id: Some(plane.to_string()),
            mdns_enabled: false,
            ..DaemonConfig::default()
        };
        config.history.enabled = false;
        config
    }

    fn hermetic_serve_options() -> ServeOptions {
        ServeOptions {
            skip_update_check: true,
            cli_no_port_mapping: true,
            cli_disable_peer_cache: true,
            ..ServeOptions::default()
        }
    }

    /// #645 item 2: on Unix, ANY open failure on an existing lockfile used
    /// to be reported as `Held` — so a lockfile the daemon merely could not
    /// open (e.g. a root-owned `instance.lock` left behind by a `sudo` run)
    /// told the operator another instance owned the dir and to kill a pid,
    /// instead of surfacing the real permission error. Only a Windows
    /// sharing violation (where the share-mode open IS the guard) means
    /// contention; on Unix an open failure is an open failure.
    #[cfg(unix)]
    #[test]
    fn unix_open_failure_on_an_existing_lockfile_is_not_reported_as_held() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A lockfile path no uid can open read+write (root included):
        // open(2) on a directory fails EISDIR — the same "open failed on
        // an existing path" shape as a root-owned file for a non-root
        // daemon, without depending on running unprivileged.
        std::fs::create_dir(dir.path().join(INSTANCE_LOCK_FILE))
            .expect("plant an unopenable lockfile");

        let err = InstanceLock::acquire(dir.path())
            .expect_err("open must fail on an unopenable lockfile");
        assert!(
            matches!(err, InstanceLockError::Open { .. }),
            "an open failure must surface as Open, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("cannot open instance lock"),
            "the real I/O failure must be surfaced: {msg}"
        );
        assert!(
            !msg.contains("owns data dir"),
            "must not read as another instance owning the dir: {msg}"
        );
        assert!(
            !msg.contains("kill"),
            "must not advise killing a phantom holder: {msg}"
        );
    }

    /// #645 item 3: two daemons with DIFFERENT data dirs but one shared
    /// configured `identity_dir` both passed the #601 guard and then loaded
    /// the same machine/agent keys — two daemons signing as one agent,
    /// uncoordinated (the #601 hazard, one directory up). The configured
    /// identity dir now carries its own instance lock: the second daemon is
    /// refused before any subsystem initialises.
    #[tokio::test]
    async fn serve_is_refused_when_another_daemon_owns_the_configured_identity_dir() {
        let shared_identity = tempfile::tempdir().expect("shared identity dir");
        // Simulate daemon A: hold the identity-dir lock (the same
        // `instance.lock` the daemon itself takes there).
        let holder = InstanceLock::acquire(shared_identity.path())
            .expect("hold the identity lock as daemon A");
        let data_dir = tempfile::tempdir().expect("distinct data dir");

        let err = match serve_with_options(
            hermetic_serve_config(
                data_dir.path(),
                Some(shared_identity.path().to_path_buf()),
                "issue-645.identity-guard",
            ),
            hermetic_serve_options(),
        )
        .await
        {
            Err(err) => err,
            Ok(handle) => {
                let _ = handle.shutdown_and_wait().await;
                panic!("a shared identity dir must be refused, not served");
            }
        };
        let msg = err.to_string();
        assert!(
            msg.contains("another x0xd instance owns identity dir"),
            "refusal must name the identity-dir ownership: {msg}"
        );
        assert!(
            msg.contains(shared_identity.path().display().to_string().as_str()),
            "refusal must name the shared identity dir: {msg}"
        );
        drop(holder);
    }

    /// #645 item 1: `Drop for ServerHandle` used to release `instance.lock`
    /// synchronously, while the supervisor task was still draining — so an
    /// embedded caller that dropped the handle and immediately re-served
    /// the same data dir briefly ran TWO servers on it (both writing
    /// api.port, history.db, and the peers cache). The lock now lives in
    /// the supervisor task: a re-serve is refused while the old server is
    /// still draining, and succeeds only after the drain has finished.
    #[tokio::test]
    async fn reserve_during_drain_is_refused_until_the_supervisor_finishes() {
        use tokio::io::AsyncWriteExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let config = hermetic_serve_config(
            dir.path(),
            Some(dir.path().join("identity")),
            "issue-645.drop-drain",
        );
        let handle = serve_with_options(config.clone(), hermetic_serve_options())
            .await
            .expect("first serve");

        // Pin the first server's drain open: an in-flight request body that
        // never completes keeps the connection active, so graceful shutdown
        // — and therefore the supervisor, and therefore the instance lock —
        // cannot finish until this connection closes.
        let token = std::fs::read_to_string(dir.path().join("api-token"))
            .expect("api token written at startup")
            .trim()
            .to_string();
        let mut stall = tokio::net::TcpStream::connect(handle.local_addr())
            .await
            .expect("connect to the api listener");
        // #661 item 3: `Expect: 100-continue` makes the server's liveness on
        // this request an OBSERVABLE protocol fact instead of a 200 ms guess:
        // hyper sends the `100 Continue` interim response only once the
        // handler starts reading the body, so reading it proves the request
        // is in flight and the graceful-shutdown drain must wait for it.
        // (The old fixed sleep could fire before the head was even accepted,
        // letting the drain finish first and the refusal assert flake.)
        let head = format!(
            "POST /publish HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {token}\r\n\
             content-type: application/json\r\nExpect: 100-continue\r\n\
             Content-Length: 65536\r\n\r\n",
            handle.local_addr(),
        );
        stall
            .write_all(head.as_bytes())
            .await
            .expect("send stalled request head");
        stall.flush().await.expect("flush stalled request head");
        let mut interim = [0u8; 128];
        let read = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            use tokio::io::AsyncReadExt;
            stall.read(&mut interim).await
        })
        .await
        .expect("server must answer the 100-continue probe within 10s")
        .expect("read the 100-continue interim response");
        let preamble = String::from_utf8_lossy(&interim[..read]);
        assert!(
            preamble.starts_with("HTTP/1.1 100"),
            "expected the 100-continue interim response, got: {preamble}"
        );

        // The overlap window: dropping the handle requests shutdown, and a
        // re-serve on the same data dir must be REFUSED while the first
        // supervisor is still draining behind the stalled request.
        drop(handle);
        let err = match serve_with_options(config.clone(), hermetic_serve_options()).await {
            Err(err) => err,
            Ok(handle) => {
                let _ = handle.shutdown_and_wait().await;
                panic!("re-serve during drain must be refused: two servers on one data dir");
            }
        };
        assert!(
            err.to_string()
                .contains("another x0xd instance owns data dir"),
            "refusal must be the instance-lock ownership error: {err}"
        );

        // Release the stall: the drain finishes, the lock is freed, and a
        // re-serve must then succeed — the guard fences overlap, it never
        // wedges the directory.
        drop(stall);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let second = loop {
            if std::time::Instant::now() > deadline {
                panic!("instance lock was not released after the drain finished");
            }
            match serve_with_options(config.clone(), hermetic_serve_options()).await {
                Ok(handle) => break handle,
                Err(err) if err.to_string().contains("another x0xd instance owns") => {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
                Err(err) => panic!("unexpected re-serve failure: {err}"),
            }
        };
        second
            .shutdown_and_wait()
            .await
            .expect("second server stops cleanly");
    }

    /// #645 item 3 (unit): the identity-dir refusal must name the identity
    /// dir — the refused daemon's data dir is NOT contended, and pointing
    /// the operator at it would send them chasing the wrong conflict.
    #[test]
    fn identity_lock_refusal_names_the_identity_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _first = InstanceLock::acquire_identity(dir.path()).expect("first identity acquire");

        let err = InstanceLock::acquire_identity(dir.path())
            .expect_err("second identity acquire must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("another x0xd instance owns identity dir"),
            "refusal must name the identity dir: {msg}"
        );
        assert!(
            msg.contains("point this daemon at a different identity_dir"),
            "advice must redirect the identity dir, not the data dir: {msg}"
        );
    }

    /// #645 item 3 (dedup): when the configured identity dir IS the data
    /// dir, the daemon must not contend with itself — flock'ing the same
    /// lockfile through a second open file description in one process
    /// fails. That layout must serve and stop cleanly.
    #[tokio::test]
    async fn serve_succeeds_when_the_configured_identity_dir_is_the_data_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = serve_with_options(
            hermetic_serve_config(
                dir.path(),
                Some(dir.path().to_path_buf()),
                "issue-645.dedup",
            ),
            hermetic_serve_options(),
        )
        .await
        .expect("identity dir == data dir must serve, not self-contend");
        handle
            .shutdown_and_wait()
            .await
            .expect("identity dir == data dir must stop cleanly");
    }

    /// #645 item 4: the Windows contention path (share-mode open) was only
    /// ever compiled by CI's Windows build job — never executed. Share-mode
    /// checks apply per open handle, so a second write-access open in the
    /// SAME process fails with ERROR_SHARING_VIOLATION exactly as a second
    /// daemon process would; this test executes it wherever Windows tests
    /// run (dev machines today; CI compiles the path in the Build matrix).
    #[cfg(windows)]
    #[test]
    fn windows_second_acquire_in_the_same_process_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _first = InstanceLock::acquire(dir.path()).expect("first acquire");

        let err = InstanceLock::acquire(dir.path())
            .expect_err("second acquire must be refused by the share-mode open");
        assert!(
            matches!(err, InstanceLockError::Held { .. }),
            "sharing violation must map to Held, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("another x0xd instance owns data dir"),
            "refusal must lead with the ownership fact: {msg}"
        );
        assert!(
            msg.contains(&format!("pid {}", std::process::id())),
            "refusal must name the holder pid: {msg}"
        );
    }
}
