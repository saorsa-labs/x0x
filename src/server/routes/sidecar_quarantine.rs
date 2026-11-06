//! `GET /diagnostics/sidecar-quarantine`: the ADR 0108 §5a quarantined
//! sidecar copies on this node (D148, ADR 0110 §5, #1597).
//!
//! The route is read-only. It lists directory entries and reads file
//! metadata. It does not open, move, delete or rewrite a file, and it does
//! not change daemon state. Copies are never deleted automatically (D148),
//! so this list tells an operator what is kept and how much disk it uses.
//!
//! The scanned files are every file that the §5a `quarantine_file` and
//! `finalize_quarantine` helpers in `named_groups/revocation_eviction.rs`
//! move aside:
//! - ADR 0110 S4, in `<data_dir>`: `revocation-evictions.evs`,
//!   `revocation-evictions.evh` (hand-off log) and
//!   `revocation-evictions.rdc` (displaced certificates).
//! - ADR 0110 S4, in `<data_dir>/treekem`: each `<stem>.evjournal` and each
//!   `<stem>.orcpend` (pending owner-recovery mandates).
//! - ADR 0109 S3, in `<data_dir>/group-recovery`: each `<stem>.grecov`.
//!
//! A copy is `<file>.q-<txid>-<h>.pending` (pending) or
//! `<file>.q-<txid>-<h>` (history). Names that do not parse are not copies
//! and are not listed. A symbolic link is not followed and is not listed.

use super::super::state::AppState;
use crate::groups::eviction as s4;
use crate::groups::recovery as s3;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;

/// `revocation_eviction/handoff_log.rs` `FILE_NAME` (private there; the
/// drift test checks that both names stay equal).
const EVH_FILE_NAME: &str = "revocation-evictions.evh";
/// `revocation_eviction/displaced_certs.rs` `FILE_NAME` (private there).
const RDC_FILE_NAME: &str = "revocation-evictions.rdc";
/// `revocation_eviction/mandate_store.rs` `EXTENSION` (`pub(super)` there).
const ORCPEND_EXTENSION: &str = "orcpend";

/// One quarantined copy.
#[derive(Debug, Serialize)]
struct QuarantinedCopy {
    /// The live sidecar file name the copy was moved aside from.
    sidecar: String,
    /// The copy's file name.
    file: String,
    /// The copy's path, relative to the data directory when it is inside it.
    path: String,
    /// The §5a transaction ID, as 32 hexadecimal characters.
    txid: String,
    /// `pending` or `history` (§5a steps 1 and 5).
    state: &'static str,
    /// Size in bytes, or `null` when the file metadata cannot be read.
    size: Option<u64>,
}

/// A directory that could not be listed. A missing directory is not an
/// error: it has no copies. Copies found before the error stay listed.
#[derive(Debug, Serialize)]
struct ScanError {
    dir: String,
    error: String,
}

/// The `GET /diagnostics/sidecar-quarantine` response body.
#[derive(Debug, Serialize)]
struct SidecarQuarantineReport {
    copies: Vec<QuarantinedCopy>,
    count: usize,
    total_bytes: u64,
    scan_errors: Vec<ScanError>,
}

/// How a directory names its live sidecar files.
#[derive(Clone, Copy)]
enum SidecarName {
    /// One fixed file name, such as `revocation-evictions.evs`.
    Fixed(&'static str),
    /// `<stem>.<extension>`, one file for each group.
    Extension(&'static str),
}

/// GET /diagnostics/sidecar-quarantine: each quarantined sidecar copy with
/// its size (D148). Read-only.
pub(in crate::server) async fn sidecar_quarantine_diagnostics(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    Json(quarantined_sidecar_copies(&state.data_dir, &state.treekem_dir).await)
}

async fn quarantined_sidecar_copies(
    data_dir: &Path,
    treekem_dir: &Path,
) -> SidecarQuarantineReport {
    let recovery_dir = data_dir.join(s3::GROUP_RECOVERY_DIR);
    let sources = [
        (data_dir, SidecarName::Fixed(s4::EVS_FILE_NAME)),
        (data_dir, SidecarName::Fixed(EVH_FILE_NAME)),
        (data_dir, SidecarName::Fixed(RDC_FILE_NAME)),
        (treekem_dir, SidecarName::Extension(s4::EVJOURNAL_EXTENSION)),
        (treekem_dir, SidecarName::Extension(ORCPEND_EXTENSION)),
        (
            recovery_dir.as_path(),
            SidecarName::Extension(s3::GROUP_RECOVERY_EXTENSION),
        ),
    ];
    let mut copies = Vec::new();
    let mut scan_errors = Vec::new();
    for (dir, sidecar) in sources {
        if let Err(error) = scan_dir(data_dir, dir, sidecar, &mut copies).await {
            scan_errors.push(ScanError {
                dir: display_path(data_dir, dir),
                error: error.to_string(),
            });
        }
    }
    copies.sort_by(|left, right| left.path.cmp(&right.path));
    let total_bytes = copies
        .iter()
        .filter_map(|copy| copy.size)
        .fold(0u64, u64::saturating_add);
    SidecarQuarantineReport {
        count: copies.len(),
        total_bytes,
        copies,
        scan_errors,
    }
}

/// Add each copy in `dir` to `copies`. A missing `dir` has no copies.
async fn scan_dir(
    data_dir: &Path,
    dir: &Path,
    sidecar: SidecarName,
    copies: &mut Vec<QuarantinedCopy>,
) -> std::io::Result<()> {
    let mut entries = match crate::w3h_inline::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    while let Some(entry) = entries.next_entry().await? {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some((live, txid, state)) = parse_copy_name(name, sidecar) else {
            continue;
        };
        let path = entry.path();
        // `symlink_metadata` does not follow a link, so a link is skipped.
        let metadata = tokio::fs::symlink_metadata(&path).await.ok();
        if metadata.as_ref().is_some_and(|meta| !meta.is_file()) {
            continue;
        }
        copies.push(QuarantinedCopy {
            sidecar: live,
            file: name.to_string(),
            path: display_path(data_dir, &path),
            txid: hex::encode(txid),
            state,
            size: metadata.map(|meta| meta.len()),
        });
    }
    Ok(())
}

/// Parse a §5a copy name into its live file name, `txid` and state. The
/// name check is [`s4::parse_quarantine_pending_name`]; a history name is
/// the pending name without `.pending`.
fn parse_copy_name(name: &str, sidecar: SidecarName) -> Option<(String, [u8; 16], &'static str)> {
    let live = match sidecar {
        SidecarName::Fixed(file) => file.to_string(),
        SidecarName::Extension(extension) => {
            let (stem, _) = name.split_once(&format!(".{extension}.q-"))?;
            if stem.is_empty() {
                return None;
            }
            format!("{stem}.{extension}")
        }
    };
    let (pending_name, state) = if name.ends_with(".pending") {
        (name.to_string(), "pending")
    } else {
        (format!("{name}.pending"), "history")
    };
    let (txid, _) = s4::parse_quarantine_pending_name(&live, &pending_name)?;
    Some((live, txid, state))
}

/// `path` relative to `data_dir`; the data directory itself is `.`.
fn display_path(data_dir: &Path, path: &Path) -> String {
    match path.strip_prefix(data_dir) {
        Ok(relative) if relative.as_os_str().is_empty() => ".".to_string(),
        Ok(relative) => relative.to_string_lossy().into_owned(),
        Err(_) => path.to_string_lossy().into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names_in(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let mut found = Vec::new();
        for entry in walk(dir) {
            let bytes = std::fs::read(&entry).unwrap();
            found.push((entry.display().to_string(), bytes));
        }
        found.sort();
        found
    }

    fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
        out
    }

    /// D148 (ADR 0110 §5, #1597): the route lists each pending and history
    /// copy of every §5a sidecar family with its size, skips live files,
    /// temp files and names that do not parse, and changes no file.
    #[tokio::test]
    async fn sidecar_quarantine_diagnostics_lists_each_copy_with_its_size() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        let treekem_dir = data_dir.join("treekem");
        let recovery_dir = data_dir.join(s3::GROUP_RECOVERY_DIR);
        std::fs::create_dir_all(&treekem_dir).unwrap();
        std::fs::create_dir_all(&recovery_dir).unwrap();

        let evs = s4::EVS_FILE_NAME;
        let evjournal = format!("g1.{}", s4::EVJOURNAL_EXTENSION);
        let grecov = s3::sidecar_file_name("g2");
        let evs_pending = s4::quarantine_pending_name(evs, &[1; 16], b"evs-a");
        let evs_history_pending = s4::quarantine_pending_name(evs, &[2; 16], b"evs-bb");
        let evs_history = s4::quarantine_history_name(&evs_history_pending)
            .unwrap()
            .to_string();
        let evj_history =
            s4::quarantine_history_name(&s4::quarantine_pending_name(&evjournal, &[3; 16], b"evj"))
                .unwrap()
                .to_string();
        let grecov_pending = s4::quarantine_pending_name(&grecov, &[4; 16], b"grecov");

        std::fs::write(data_dir.join(evs), b"live").unwrap();
        std::fs::write(data_dir.join(&evs_pending), b"12345").unwrap();
        std::fs::write(data_dir.join(&evs_history), b"1234567").unwrap();
        std::fs::write(
            data_dir.join(format!("{evs}.tmp-{}", "01".repeat(16))),
            b"t",
        )
        .unwrap();
        std::fs::write(
            data_dir.join(format!("{evs}.q-zz-{}", "a".repeat(32))),
            b"x",
        )
        .unwrap();
        std::fs::write(
            data_dir.join(format!(
                "other.evs.q-{}-{}",
                "01".repeat(16),
                "a".repeat(32)
            )),
            b"x",
        )
        .unwrap();
        std::fs::write(treekem_dir.join(&evjournal), b"live").unwrap();
        std::fs::write(treekem_dir.join(&evj_history), b"123").unwrap();
        std::fs::write(treekem_dir.join("g1.snap"), b"snap").unwrap();
        std::fs::write(
            treekem_dir.join(format!(
                ".evjournal.q-{}-{}",
                "01".repeat(16),
                "a".repeat(32)
            )),
            b"x",
        )
        .unwrap();
        std::fs::write(recovery_dir.join(&grecov_pending), b"12345678901").unwrap();
        // #1804 review: the other files that `quarantine_file` moves aside.
        let evh_pending = s4::quarantine_pending_name(EVH_FILE_NAME, &[5; 16], b"evh");
        let rdc_history = s4::quarantine_history_name(&s4::quarantine_pending_name(
            RDC_FILE_NAME,
            &[6; 16],
            b"rdc",
        ))
        .unwrap()
        .to_string();
        let orcpend = format!("g1.{ORCPEND_EXTENSION}");
        let orcpend_pending = s4::quarantine_pending_name(&orcpend, &[7; 16], b"orc");
        std::fs::write(data_dir.join(EVH_FILE_NAME), b"live").unwrap();
        std::fs::write(data_dir.join(&evh_pending), b"12").unwrap();
        std::fs::write(data_dir.join(&rdc_history), b"1234567890123").unwrap();
        std::fs::write(treekem_dir.join(&orcpend), b"live").unwrap();
        std::fs::write(treekem_dir.join(&orcpend_pending), b"12345678901234567").unwrap();
        // A link with a copy name is not followed and is not listed.
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            data_dir.join(&evs_pending),
            data_dir.join(s4::quarantine_pending_name(evs, &[8; 16], b"link")),
        )
        .unwrap();

        let before = names_in(data_dir);
        let report = quarantined_sidecar_copies(data_dir, &treekem_dir).await;
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(names_in(data_dir), before, "the listing changes no file");

        assert_eq!(json["count"], 7, "{json}");
        assert_eq!(json["total_bytes"], 5 + 7 + 3 + 11 + 2 + 13 + 17, "{json}");
        assert_eq!(json["scan_errors"], serde_json::json!([]));
        let rows: Vec<(String, String, String, String, u64)> = json["copies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|copy| {
                (
                    copy["path"].as_str().unwrap().to_string(),
                    copy["sidecar"].as_str().unwrap().to_string(),
                    copy["txid"].as_str().unwrap().to_string(),
                    copy["state"].as_str().unwrap().to_string(),
                    copy["size"].as_u64().unwrap(),
                )
            })
            .collect();
        let mut expected = vec![
            (
                Path::new(s3::GROUP_RECOVERY_DIR)
                    .join(&grecov_pending)
                    .display()
                    .to_string(),
                grecov.clone(),
                "04".repeat(16),
                "pending".to_string(),
                11,
            ),
            (
                evs_pending.clone(),
                evs.to_string(),
                "01".repeat(16),
                "pending".to_string(),
                5,
            ),
            (
                evs_history.clone(),
                evs.to_string(),
                "02".repeat(16),
                "history".to_string(),
                7,
            ),
            (
                Path::new("treekem")
                    .join(&evj_history)
                    .display()
                    .to_string(),
                evjournal.clone(),
                "03".repeat(16),
                "history".to_string(),
                3,
            ),
            (
                evh_pending.clone(),
                EVH_FILE_NAME.to_string(),
                "05".repeat(16),
                "pending".to_string(),
                2,
            ),
            (
                rdc_history.clone(),
                RDC_FILE_NAME.to_string(),
                "06".repeat(16),
                "history".to_string(),
                13,
            ),
            (
                Path::new("treekem")
                    .join(&orcpend_pending)
                    .display()
                    .to_string(),
                orcpend.clone(),
                "07".repeat(16),
                "pending".to_string(),
                17,
            ),
        ];
        expected.sort();
        assert_eq!(rows, expected);
    }

    /// The mirrored names must equal the private constants of the files
    /// that own them (#1804 review). If one of these files renames its
    /// constant, this test fails until the mirror here is updated.
    #[test]
    fn mirrored_sidecar_names_match_their_source_files() {
        let sources = [
            (
                include_str!("named_groups/revocation_eviction/handoff_log.rs"),
                format!("const FILE_NAME: &str = \"{EVH_FILE_NAME}\";"),
            ),
            (
                include_str!("named_groups/revocation_eviction/displaced_certs.rs"),
                format!("const FILE_NAME: &str = \"{RDC_FILE_NAME}\";"),
            ),
            (
                include_str!("named_groups/revocation_eviction/mandate_store.rs"),
                format!("pub(super) const EXTENSION: &str = \"{ORCPEND_EXTENSION}\";"),
            ),
        ];
        for (source, line) in sources {
            assert!(source.contains(&line), "missing `{line}`");
        }
    }

    /// The data directory itself is reported as `.`, never as "".
    #[test]
    fn the_data_directory_is_displayed_as_dot() {
        let data_dir = Path::new("/var/x0x");
        assert_eq!(display_path(data_dir, data_dir), ".");
        assert_eq!(display_path(data_dir, &data_dir.join("treekem")), "treekem");
        assert_eq!(
            display_path(data_dir, Path::new("/elsewhere")),
            "/elsewhere"
        );
    }

    /// A data directory with no sidecar directories has no copies and no
    /// scan errors.
    #[tokio::test]
    async fn sidecar_quarantine_diagnostics_is_empty_without_copies() {
        let dir = tempfile::tempdir().unwrap();
        let report = quarantined_sidecar_copies(dir.path(), &dir.path().join("treekem")).await;
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"copies": [], "count": 0, "total_bytes": 0, "scan_errors": []})
        );
    }
}
