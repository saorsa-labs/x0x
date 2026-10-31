//! Bounded regular-file reads and backup-preserving restore barriers.
use super::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub(super) fn hash(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_BINARY_BYTES {
        return Err(invalid("not a bounded regular binary"));
    }
    hash_bounded(&mut file, MAX_BINARY_BYTES)
}

const MAX_BINARY_BYTES: u64 = 200 * 1024 * 1024;

/// Hashes at most `limit` bytes. A source that grows past `limit` while it
/// is read is refused, not hashed in part.
fn hash_bounded(source: impl Read, limit: u64) -> io::Result<[u8; 32]> {
    let mut source = source.take(limit.saturating_add(1));
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    let mut total: u64 = 0;
    loop {
        let n = source.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > limit {
            return Err(invalid("binary grew past the read limit"));
        }
        hash.update(&buf[..n]);
    }
    Ok(hash.finalize().into())
}

pub(super) fn restore_one(a: &journal::ArtifactPlan) -> io::Result<()> {
    let parent = a
        .target_path
        .parent()
        .ok_or_else(|| invalid("no install parent"))?;
    let temporary = parent.join(format!(".x0x-restore-{}", uuid::Uuid::new_v4()));
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&a.backup_path)?;
    if !source.metadata()?.is_file() {
        return Err(invalid("rollback copy is not regular"));
    }
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(source.metadata()?.permissions().mode() & 0o777)
        .open(&temporary)?;
    let result = (|| {
        target.set_permissions(PermissionsExt::from_mode(
            source.metadata()?.permissions().mode() & 0o777,
        ))?;
        io::copy(&mut source, &mut target)?;
        target.flush()?;
        target.sync_all()?;
        if hash(&temporary)? != a.previous_sha256 {
            return Err(invalid("restore copy hash mismatch"));
        }
        std::fs::rename(&temporary, &a.target_path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn restore_changes_installed_bytes_and_retains_the_backup() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("daemon");
        let backup = dir.path().join("old");
        std::fs::write(&target, b"candidate").unwrap();
        std::fs::write(&backup, b"previous").unwrap();
        let plan = journal::ArtifactPlan {
            target_path: target.clone(),
            staged_path: dir.path().join("staged"),
            backup_path: backup.clone(),
            previous_sha256: hash(&backup).unwrap(),
            candidate_sha256: hash(&target).unwrap(),
        };
        restore_one(&plan).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"previous");
        assert_eq!(std::fs::read(&backup).unwrap(), b"previous");
        // A second restore reconciles the same old bytes without consuming
        // the protected rollback copy.
        restore_one(&plan).unwrap();
        assert_eq!(hash(&target).unwrap(), plan.previous_sha256);
        assert_eq!(hash(&backup).unwrap(), plan.previous_sha256);
    }

    #[test]
    fn bad_backup_never_replaces_the_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("daemon");
        let backup = dir.path().join("old");
        std::fs::write(&target, b"candidate").unwrap();
        std::fs::write(&backup, b"damaged").unwrap();
        let plan = journal::ArtifactPlan {
            target_path: target.clone(),
            staged_path: dir.path().join("staged"),
            backup_path: backup.clone(),
            previous_sha256: [3; 32],
            candidate_sha256: hash(&target).unwrap(),
        };
        assert!(restore_one(&plan).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"candidate");
        assert_eq!(std::fs::read(backup).unwrap(), b"damaged");
    }

    #[test]
    fn launcher_hash_is_sha256_of_regular_file_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon");
        std::fs::write(&path, b"candidate bytes").unwrap();
        let expected: [u8; 32] = Sha256::digest(b"candidate bytes").into();
        assert_eq!(hash(&path).unwrap(), expected);
        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(hash(&empty).unwrap(), <[u8; 32]>::from(Sha256::digest(b"")));
    }

    #[test]
    fn launcher_hash_refuses_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("daemon");
        let link = dir.path().join("link");
        std::fs::write(&target, b"candidate").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = hash(&link).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ELOOP));
    }

    #[test]
    fn launcher_hash_refuses_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let error = hash(dir.path()).unwrap_err();
        assert_eq!(error.to_string(), "not a bounded regular binary");
    }

    #[test]
    fn launcher_hash_refuses_a_fifo_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: name is a live nul-terminated path.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        // With no writer, a blocking open would hang here.
        let (done, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(hash(&fifo).map_err(|error| error.to_string()));
        });
        let result = wait
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        assert_eq!(result.unwrap_err(), "not a bounded regular binary");
    }

    #[test]
    fn hash_refuses_a_source_longer_than_the_limit() {
        let bytes = [7u8; 100];
        assert_eq!(
            hash_bounded(&bytes[..], 100).unwrap(),
            <[u8; 32]>::from(Sha256::digest(bytes))
        );
        assert!(hash_bounded(&bytes[..], 99).is_err());
    }
}
