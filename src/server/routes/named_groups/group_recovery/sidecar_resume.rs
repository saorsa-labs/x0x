//! ADR 0109 §4 (D120) and ADR 0108 §5a "Resume at startup" for the S3
//! sidecar `<stem>.grecov` (#1533 review).
//!
//! The quarantine transaction moves a damaged `F` to
//! `F.q-<txid>-<h>.pending`, fsyncs `D`, verifies the copy, writes the
//! replacement at `F` and then marks the copy as history. A crash between
//! the first rename and the last rename leaves a pending copy, and maybe
//! no `F`. The loader reads only names that end in `.grecov`, so before
//! this module nothing processed that state: the group lost its sidecar
//! state with no typed fault. [`resume_pending`] runs before the loader,
//! under the sidecar writer lock, and finishes each open transaction:
//!
//! 1. **Barrier.** fsync `D` before any read.
//! 2. **Verify.** Each pending copy is checked against the `h` in its name.
//!    A copy that fails stays pending and its file shows
//!    `sidecar_quarantine_failed {step: verify}`.
//! 3. **Classify `F`.** Missing: one empty replacement covers the verified
//!    set `V` (none when `V` is empty). Valid: `F` is kept. Newer or
//!    unreadable: `F` and every pending copy are left as they are (the
//!    loader reports the fault). Damaged: `F` is quarantined as its own
//!    transaction, its `txid` joins `V`, and the missing rule applies.
//! 4. **Finalize.** Each copy in `V` becomes history, in `txid` order.
//!
//! No step reduces containment: a replacement is empty, so the legacy
//! record (and any S3 placeholder) governs, as at a first quarantine.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use crate::groups::eviction as s4;
use crate::groups::recovery::{self as s3, GroupRecoveryDecodeError, GroupRecoveryV1};

async fn sync_dir(dir: &Path) -> bool {
    // `sync_parent_dir_for_path` fsyncs the parent of its argument.
    let probe = dir.join("probe");
    tokio::task::spawn_blocking(move || super::super::sync_parent_dir_for_path(&probe))
        .await
        .is_ok_and(|result| result.is_ok())
}

/// Finish every open quarantine transaction in `dir`. Returns the sidecar
/// file names (`F`) whose resume failed, with the failed §5a step; S3 runs
/// memory-only for each until a later load succeeds.
pub(super) async fn resume_pending(dir: &Path) -> HashMap<String, &'static str> {
    let mut failed = HashMap::new();
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return failed;
    };
    let mut names = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Some(name) = entry.file_name().to_str() {
            names.push(name.to_string());
        }
    }
    let marker = format!(".{}.q-", s3::GROUP_RECOVERY_EXTENSION);
    let mut open: BTreeMap<String, Vec<([u8; 16], String, PathBuf)>> = BTreeMap::new();
    for name in &names {
        let Some(at) = name.find(&marker) else {
            continue;
        };
        let file = &name[..at + marker.len() - 3];
        if let Some((txid, h)) = s4::parse_quarantine_pending_name(file, name) {
            open.entry(file.to_string())
                .or_default()
                .push((txid, h, dir.join(name)));
        }
    }
    if open.is_empty() {
        return failed;
    }
    if !sync_dir(dir).await {
        for file in open.into_keys() {
            failed.insert(file, "fsync");
        }
        return failed;
    }
    for (file, mut copies) in open {
        copies.sort_by_key(|copy| copy.0);
        if let Err(step) = resume_file(dir, &file, copies, &names).await {
            failed.insert(file, step);
        }
    }
    failed
}

async fn resume_file(
    dir: &Path,
    file: &str,
    copies: Vec<([u8; 16], String, PathBuf)>,
    names: &[String],
) -> Result<(), &'static str> {
    let path = dir.join(file);
    let mut verified: Vec<([u8; 16], PathBuf)> = Vec::new();
    let mut verify_failed = false;
    for (txid, h, copy) in copies {
        match tokio::fs::read(&copy).await {
            Ok(bytes) if s4::quarantine_hash_hex(&bytes) == h => verified.push((txid, copy)),
            _ => verify_failed = true,
        }
    }
    let missing = match tokio::fs::read(&path).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        // Unreadable: leave `F` and every copy; the loader reports it.
        Err(_) => return Ok(()),
        Ok(bytes) => match s3::decode_sidecar(&bytes) {
            Ok(_) => false,
            // Newer: never touched; a binary that reads it resumes later.
            Err(GroupRecoveryDecodeError::NewerFormat(_)) => return Ok(()),
            Err(GroupRecoveryDecodeError::Damaged(cause)) => {
                tracing::warn!(
                    file,
                    cause,
                    "ADR 0109 S3: damaged sidecar during resume; quarantining (D120)"
                );
                let quarantined =
                    super::super::revocation_eviction::quarantine_file(&path, &bytes).await?;
                verified.push(quarantined);
                true
            }
        },
    };
    verified.sort_by_key(|copy| copy.0);
    if missing {
        if verified.is_empty() {
            return Err("verify");
        }
        let temp_prefix = format!("{file}.tmp-");
        for name in names.iter().filter(|name| name.starts_with(&temp_prefix)) {
            let _ = tokio::fs::remove_file(dir.join(name)).await;
        }
        let rebuilt = GroupRecoveryV1 {
            generation: 1,
            rebuilt_from: verified.iter().map(|(txid, _)| *txid).collect(),
            ..GroupRecoveryV1::default()
        };
        let bytes = s3::encode_sidecar(&rebuilt).map_err(|_| "replace")?;
        let first = verified.first().map(|(txid, _)| *txid);
        super::super::revocation_eviction::write_bytes_durably(&path, &bytes, first.as_ref())
            .await
            .map_err(|_| "replace")?;
        tracing::warn!(
            file,
            covered = verified.len(),
            "ADR 0109 S3: resumed an interrupted sidecar quarantine; empty replacement written"
        );
    }
    for (_, copy) in &verified {
        if !super::super::revocation_eviction::finalize_quarantine(copy).await {
            return Err("finalize");
        }
    }
    if verify_failed {
        return Err("verify");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const F: &str = "abc.grecov";

    fn body(generation: u64) -> Vec<u8> {
        s3::encode_sidecar(&GroupRecoveryV1 {
            generation,
            ..GroupRecoveryV1::default()
        })
        .expect("encode")
    }

    /// Step 1 of the transaction ran: `F` is at its pending name.
    async fn renamed_aside(dir: &Path, damaged: &[u8]) -> ([u8; 16], PathBuf) {
        let txid = [7u8; 16];
        let pending = dir.join(s4::quarantine_pending_name(F, &txid, damaged));
        tokio::fs::write(&pending, damaged).await.expect("write");
        (txid, pending)
    }

    async fn names(dir: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let mut entries = tokio::fs::read_dir(dir).await.expect("read_dir");
        while let Ok(Some(entry)) = entries.next_entry().await {
            out.push(entry.file_name().to_string_lossy().into_owned());
        }
        out.sort();
        out
    }

    fn rebuilt_from(bytes: &[u8]) -> Vec<[u8; 16]> {
        s3::decode_sidecar(bytes).expect("valid F").rebuilt_from
    }

    async fn loaded_rebuild(dir: &Path) -> Vec<[u8; 16]> {
        let (loaded, faults) = super::super::scan_sidecar_dir(dir, true).await;
        assert!(faults.is_empty(), "{faults:?}");
        loaded
            .get("abc")
            .expect("the interrupted quarantine is resumed: the group has a sidecar")
            .rebuilt_from
            .clone()
    }

    #[test]
    fn the_sidecar_file_name_is_the_pending_prefix() {
        assert_eq!(s3::sidecar_file_name("abc"), F);
    }

    /// Cut points after step 1 (rename), step 2 (fsync) and step 3
    /// (verify) leave the same disk state: no `F`, one pending copy. The
    /// load writes one empty replacement covering it and marks the copy as
    /// history; the original bytes are kept.
    #[tokio::test]
    async fn a_quarantine_cut_before_the_replacement_is_resumed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let damaged = b"X0GRCV1\0damaged".to_vec();
        let (txid, pending) = renamed_aside(dir.path(), &damaged).await;
        assert_eq!(loaded_rebuild(dir.path()).await, vec![txid]);
        assert!(!pending.exists(), "the pending copy is finalized");
        let history = dir.path().join(
            s4::quarantine_history_name(
                pending.file_name().and_then(|n| n.to_str()).expect("name"),
            )
            .expect("history name"),
        );
        assert_eq!(tokio::fs::read(&history).await.expect("history"), damaged);
    }

    /// Cut inside step 4, after the temporary replacement was written and
    /// before its rename: the temporary file goes, and one replacement
    /// covers the pending copy.
    #[tokio::test]
    async fn a_quarantine_cut_inside_the_replacement_write_is_resumed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (txid, _) = renamed_aside(dir.path(), b"damaged").await;
        let temp = dir.path().join(format!("{F}.tmp-{}", hex::encode(txid)));
        tokio::fs::write(&temp, body(9)).await.expect("write");
        assert_eq!(loaded_rebuild(dir.path()).await, vec![txid]);
        assert!(!temp.exists());
        assert!(names(dir.path())
            .await
            .iter()
            .all(|n| !n.ends_with(".pending")));
    }

    /// Cut after step 4's rename and before step 5: `F` is the replacement.
    /// It is kept byte-identical and the copy is finalized.
    #[tokio::test]
    async fn a_quarantine_cut_before_finalize_keeps_the_replacement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (txid, pending) = renamed_aside(dir.path(), b"damaged").await;
        let replacement = s3::encode_sidecar(&GroupRecoveryV1 {
            generation: 1,
            rebuilt_from: vec![txid],
            ..GroupRecoveryV1::default()
        })
        .expect("encode");
        tokio::fs::write(dir.path().join(F), &replacement)
            .await
            .expect("write");
        assert_eq!(loaded_rebuild(dir.path()).await, vec![txid]);
        assert_eq!(
            tokio::fs::read(dir.path().join(F)).await.expect("F"),
            replacement
        );
        assert!(!pending.exists());
    }

    /// Cut after step 5 (control): only history remains, nothing changes.
    #[tokio::test]
    async fn a_finished_quarantine_is_left_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        tokio::fs::write(dir.path().join(F), body(4))
            .await
            .expect("write");
        let history = dir
            .path()
            .join(format!("{F}.q-{}-{}", "07".repeat(16), "a".repeat(32)));
        tokio::fs::write(&history, b"old").await.expect("write");
        let (loaded, faults) = super::super::scan_sidecar_dir(dir.path(), true).await;
        assert!(faults.is_empty());
        assert_eq!(loaded.get("abc").map(|b| b.generation), Some(4));
        assert_eq!(names(dir.path()).await.len(), 2);
    }

    /// A pending copy that fails verification stays pending, no
    /// replacement covers it, and the file shows `quarantine_failed
    /// {step: verify}` (memory-only); a damaged `F` beside a verified copy
    /// is quarantined and one replacement covers both.
    #[tokio::test]
    async fn verify_failure_and_a_damaged_file_follow_the_resume_rules() {
        let dir = tempfile::tempdir().expect("tempdir");
        let txid = [3u8; 16];
        let bad = dir
            .path()
            .join(s4::quarantine_pending_name(F, &txid, b"original"));
        tokio::fs::write(&bad, b"bit rot").await.expect("write");
        let (loaded, faults) = super::super::scan_sidecar_dir(dir.path(), true).await;
        assert!(loaded.is_empty());
        assert!(matches!(
            faults.get("abc"),
            Some(super::super::SidecarFault::QuarantineFailed { step, .. }) if step == "verify"
        ));
        assert!(bad.exists() && !dir.path().join(F).exists());

        let other = tempfile::tempdir().expect("tempdir");
        let (txid, _) = renamed_aside(other.path(), b"first").await;
        tokio::fs::write(other.path().join(F), b"X0GRCV1\0also damaged")
            .await
            .expect("write");
        let covered = loaded_rebuild(other.path()).await;
        assert_eq!(covered.len(), 2);
        assert!(covered.contains(&txid));
        assert_eq!(
            rebuilt_from(&tokio::fs::read(other.path().join(F)).await.expect("F")),
            covered
        );
    }
}
