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
//! for the lifetime of the returned [`crate::server::ServerHandle`]. It is
//! deliberately independent of the history subsystem.
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

/// Name of the lockfile inside the data directory.
pub(super) const INSTANCE_LOCK_FILE: &str = "instance.lock";

/// The held single-instance lock.
///
/// Keeps the underlying file open for the daemon's lifetime; dropping the
/// value (with the [`crate::server::ServerHandle`] that owns it) releases the
/// lock. Process exit releases it unconditionally.
pub struct InstanceLock {
    /// The locked file. Underscored: merely holding it open is the guard.
    _file: File,
}

impl fmt::Debug for InstanceLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstanceLock(<held>)")
    }
}

/// Failure to establish the single-instance guard.
#[derive(Debug)]
pub enum InstanceLockError {
    /// The lockfile could not be created or opened (permissions, I/O error).
    Open {
        data_dir: PathBuf,
        path: PathBuf,
        source: std::io::Error,
    },
    /// A live process already holds the lock — another daemon owns the data
    /// directory. `holder_pid` is read best-effort from the lockfile; it may
    /// be `None` (unreadable or unrecorded) without weakening the refusal,
    /// which the kernel-level lock alone decided.
    Held {
        data_dir: PathBuf,
        path: PathBuf,
        holder_pid: Option<u32>,
    },
}

impl fmt::Display for InstanceLockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open {
                data_dir,
                path,
                source,
            } => write!(
                f,
                "cannot open instance lock {} in data dir {}: {source}",
                path.display(),
                data_dir.display()
            ),
            Self::Held {
                data_dir,
                path,
                holder_pid,
            } => {
                write!(
                    f,
                    "another x0xd instance owns data dir {} (instance lock {}",
                    data_dir.display(),
                    path.display()
                )?;
                match holder_pid {
                    Some(pid) => write!(
                        f,
                        " held by pid {pid}); stop it first (x0x stop or kill {pid}), or start this daemon with a different --name / data_dir"
                    ),
                    None => write!(
                        f,
                        " is already held); stop the running daemon first (x0x stop), or start this daemon with a different --name / data_dir"
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
    /// Acquire the single-instance lock for `data_dir`.
    ///
    /// The caller must have created `data_dir` (the daemon does this
    /// immediately before calling). On success the returned guard MUST be
    /// kept alive for as long as the daemon intends to own the directory;
    /// dropping it releases the lock. On contention the error names the data
    /// dir and, best-effort, the pid of the holder.
    pub fn acquire(data_dir: &Path) -> Result<Self, InstanceLockError> {
        let path = data_dir.join(INSTANCE_LOCK_FILE);
        let file = open_lock_file(&path).map_err(|source| {
            // On Windows the share-mode open IS the guard, so contention
            // surfaces here as an open failure on an existing file — map
            // that shape to `Held` (with a best-effort pid read) rather
            // than a raw I/O error. On Unix `open` itself cannot contend
            // (flock is taken separately below), so this arm is only
            // genuine I/O failure.
            if path.exists() {
                let holder_pid = read_holder_pid(&path);
                InstanceLockError::Held {
                    data_dir: data_dir.to_path_buf(),
                    path: path.clone(),
                    holder_pid,
                }
            } else {
                InstanceLockError::Open {
                    data_dir: data_dir.to_path_buf(),
                    path: path.clone(),
                    source,
                }
            }
        })?;

        // Unix: take the advisory exclusive lock now, non-blocking.
        let locked = try_lock_exclusive(&file).map_err(|source| InstanceLockError::Open {
            data_dir: data_dir.to_path_buf(),
            path: path.clone(),
            source,
        })?;
        if !locked {
            let holder_pid = read_holder_pid(&path);
            return Err(InstanceLockError::Held {
                data_dir: data_dir.to_path_buf(),
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
}
