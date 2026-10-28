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
    if !file.metadata()?.is_file() || file.metadata()?.len() > 200 * 1024 * 1024 {
        return Err(invalid("not a bounded regular binary"));
    }
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
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

#[cfg(test)]
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
}
