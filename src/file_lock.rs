//! Cross-process advisory file locks, shared by the daemon instance lock
//! (`server::instance_lock`, #601) and the `revocations-v3.bin` writer
//! (#926). The lock rides the open file description (`flock` on Unix, a
//! write-share-denying open on Windows), so the kernel releases it when the
//! holder closes the file or exits — even on crash.

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::time::Duration;

/// An exclusive advisory lock, held until dropped.
#[derive(Debug)]
pub(crate) struct FileLockGuard {
    _file: File,
}

/// Take an exclusive lock on `path` (created if missing), retrying every
/// `poll` until `timeout`. `on_contended` runs once each time another holder
/// is observed (a test hook; production passes a no-op).
///
/// # Errors
/// An I/O failure other than contention, or `TimedOut` once `timeout`
/// elapses while another holder keeps the lock.
pub(crate) async fn lock_exclusive_with_retry(
    path: &Path,
    poll: Duration,
    timeout: Duration,
    on_contended: impl Fn(),
) -> std::io::Result<FileLockGuard> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match open_lock_file(path) {
            Ok(file) => {
                if try_lock_exclusive(&file)? {
                    return Ok(FileLockGuard { _file: file });
                }
            }
            Err(e) if open_failure_means_contention(&e) => {}
            Err(e) => return Err(e),
        }
        on_contended();
        if tokio::time::Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("lock {} still held after {timeout:?}", path.display()),
            ));
        }
        tokio::time::sleep(poll).await;
    }
}

#[cfg(unix)]
pub(crate) fn open_lock_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

#[cfg(windows)]
pub(crate) fn open_lock_file(path: &Path) -> std::io::Result<File> {
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
pub(crate) fn open_failure_means_contention(source: &std::io::Error) -> bool {
    const ERROR_SHARING_VIOLATION: i32 = 32;
    source.raw_os_error() == Some(ERROR_SHARING_VIOLATION)
}

/// Unix has no open-time contention (`flock` is taken separately in
/// [`try_lock_exclusive`]), so no open failure ever means "held".
#[cfg(not(windows))]
pub(crate) fn open_failure_means_contention(_source: &std::io::Error) -> bool {
    false
}

/// Take the exclusive lock non-blocking. `Ok(true)` = acquired,
/// `Ok(false)` = held by another live process, `Err` = lock syscall failure.
#[cfg(unix)]
pub(crate) fn try_lock_exclusive(file: &File) -> std::io::Result<bool> {
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
pub(crate) fn try_lock_exclusive(_file: &File) -> std::io::Result<bool> {
    // The share-mode(READ)-only open in `open_lock_file` is the guard:
    // reaching here means our open succeeded, so no other process holds a
    // write handle. A contending daemon fails inside `open_lock_file` and
    // is mapped to `Held` there.
    Ok(true)
}
