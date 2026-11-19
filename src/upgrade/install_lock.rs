//! The install lock guard (#2012). Its own file so the launcher's test
//! build, which includes `prepare.rs` by path, can include it too.

use std::fs::File;
use std::io;

/// One install lock file, locked. A value exists only after its lock was
/// taken (`take`, or a `try_take` that succeeded), so holding one proves
/// the holder has the lock (#2074 review). The lock is held until the value
/// is dropped. Defined outside the Unix-only `prepare` so the Windows form
/// of `acquire_host_upgrade_lock` builds.
pub(crate) struct InstallLock(File);

impl InstallLock {
    /// Take the lock on an install lock file; waits for another holder.
    pub(crate) fn take(file: File) -> io::Result<Self> {
        file.lock()?;
        Ok(Self(file))
    }

    /// The lock if no other holder has it, else `None`.
    #[cfg(unix)]
    pub(crate) fn try_take(file: File) -> io::Result<Option<Self>> {
        match file.try_lock() {
            Ok(()) => Ok(Some(Self(file))),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(error)) => Err(error),
        }
    }

    /// The locked file, for checks that only read it.
    #[cfg(unix)]
    pub(crate) fn file(&self) -> &File {
        &self.0
    }

    /// The open file, which keeps holding the lock until it is dropped.
    pub(crate) fn into_file(self) -> File {
        self.0
    }
}
