#![cfg(test)]
//! #1368 (#481 item 4): a crash at any write barrier of the TreeKEM
//! persist recovers one consistent state.
//!
//! The two journaled transactions write their files in a fixed order:
//!
//! - the seal (`persist_treekem_and_named_groups_atomic_locked`):
//!   `.hsjournal`, legacy journal (the commit point), Home-Suite sidecar,
//!   TreeKEM snapshot, `named_groups.json`, then the two journal deletes;
//! - the rebind of a metadata-only change (`prepare_rebind_journal_for_groups`,
//!   `save_named_groups_store_checked`, `apply_rebind_journal_snapshot`):
//!   `.hsjournal`, legacy journal, sidecar, `named_groups.json`, then the
//!   sidecar journal apply, the snapshot and the two journal deletes.
//!
//! A test hook (`take_crash_image`) copies the live files and the journals
//! at each barrier, as a crash there would leave them. The daemon's own
//! startup recovery then runs on each copy, in `serve()` order. Each copy
//! must recover either the whole old state or the whole new state, with
//! the TreeKEM group restored and no journal left behind.
//!
//! Inert: tempdirs only, no network config, no sockets.

use super::issue1187_durable_journal::{apply_seal, rebind_fixture, rename_via_api, seal_fixture};
use super::*;

/// One crash copy: the barrier name and the directory that holds it.
struct CrashImage {
    barrier: String,
    root: PathBuf,
}

/// Armed test data directories (by `treekem_dir`), with the copies taken
/// so far. Path-scoped, so concurrent tests do not see each other.
static ARMED: std::sync::Mutex<Vec<(PathBuf, PathBuf, Vec<CrashImage>)>> =
    std::sync::Mutex::new(Vec::new());

const NAMED: &str = "named_groups.json";
const TREEKEM: &str = "treekem";

fn copy_tree(from: &FsPath, to: &FsPath) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

/// Called at each barrier of the journaled persists. When `state`'s data
/// directory is armed, copy `named_groups.json`, the Home-Suite sidecar
/// and the TreeKEM directory as they are now.
pub(in crate::server) fn take_crash_image(state: &AppState, barrier: &str) {
    let mut armed = ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some((_, out, images)) = armed
        .iter_mut()
        .find(|(treekem_dir, _, _)| *treekem_dir == state.treekem_dir)
    else {
        return;
    };
    let root = out.join(format!("{:02}-{barrier}", images.len()));
    let copied = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(&root)?;
        for (live, name) in [
            (&state.named_groups_path, NAMED),
            (&state.home_suite_groups_path, HOME_SUITE_GROUPS_FILE),
        ] {
            if live.exists() {
                std::fs::copy(live, root.join(name))?;
            }
        }
        copy_tree(&state.treekem_dir, &root.join(TREEKEM))
    })();
    assert!(copied.is_ok(), "crash image at {barrier}: {copied:?}");
    images.push(CrashImage {
        barrier: barrier.to_string(),
        root,
    });
}

/// Arms `state` for crash copies until dropped.
struct Armed {
    treekem_dir: PathBuf,
    _out: tempfile::TempDir,
}

impl Armed {
    fn new(state: &AppState) -> Result<Self> {
        let out = tempfile::tempdir()?;
        ARMED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((
                state.treekem_dir.clone(),
                out.path().to_path_buf(),
                Vec::new(),
            ));
        Ok(Self {
            treekem_dir: state.treekem_dir.clone(),
            _out: out,
        })
    }

    /// Stops copying and returns the copies taken.
    fn take(&self) -> Vec<CrashImage> {
        let mut armed = ARMED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        armed
            .iter()
            .position(|(dir, _, _)| *dir == self.treekem_dir)
            .map(|idx| armed.swap_remove(idx).2)
            .unwrap_or_default()
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        let _ = self.take();
    }
}

/// The daemon's startup recovery on one crash copy, in `serve()` order.
async fn restart_image(
    state: &AppState,
    image: &CrashImage,
) -> Result<(
    HashMap<String, x0x::groups::GroupInfo>,
    HashMap<String, Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>>>,
)> {
    let named = image.root.join(NAMED);
    let sidecar = image.root.join(HOME_SUITE_GROUPS_FILE);
    let treekem_dir = image.root.join(TREEKEM);
    recover_treekem_named_journals(&named, &sidecar, &treekem_dir).await?;
    recover_home_suite_sidecar_journals(&sidecar, &treekem_dir).await?;
    let merged = load_named_groups_merged(&named, &sidecar).await?;
    let treekem = restore_treekem_groups(&merged, state.agent.as_ref(), &treekem_dir).await;
    Ok((merged, treekem))
}

fn journals_left(image: &CrashImage, group_id: &str) -> Vec<String> {
    let treekem_dir = image.root.join(TREEKEM);
    [
        treekem_journal_path(&treekem_dir, group_id),
        treekem_home_suite_journal_path(&treekem_dir, group_id),
    ]
    .into_iter()
    .filter(|path| path.exists())
    .map(|path| path.display().to_string())
    .collect()
}

/// The barriers each transaction must pass, in order. A barrier missing
/// from the copies means the hook moved or the write order changed.
fn assert_barriers(images: &[CrashImage], expected: &[&str]) {
    let seen: Vec<&str> = images.iter().map(|image| image.barrier.as_str()).collect();
    assert_eq!(
        seen, expected,
        "#1368: the write barriers of the transaction"
    );
}

#[tokio::test]
async fn issue1368_seal_crash_at_each_barrier_recovers_one_state() -> Result<()> {
    let fixture = seal_fixture(0x68).await?;
    let armed = Armed::new(&fixture.state)?;
    let applied = apply_seal(&fixture).await;
    let images = armed.take();
    assert!(applied.is_ok(), "the unfaulted seal commits: {applied:?}");
    assert_barriers(
        &images,
        &[
            "seal-1-hsjournal",
            "seal-2-journal",
            "seal-3-sidecar",
            "seal-4-snapshot",
            "seal-5-named",
            "seal-6-journal-removed",
            "seal-7-done",
        ],
    );
    let old = (false, Some(fixture.base_epoch));
    let new = (true, Some(fixture.expected_epoch));
    for image in &images {
        let (merged, treekem) = restart_image(&fixture.state, image).await?;
        let loaded = (
            merged
                .get(&fixture.group_id)
                .is_some_and(|info| info.has_active_member(&fixture.added_hex)),
            match treekem.get(&fixture.group_id) {
                Some(group) => Some(group.lock().await.epoch()),
                None => None,
            },
        );
        // Before the commit point the old state, from it on the new one.
        let want = if image.barrier == "seal-1-hsjournal" {
            old
        } else {
            new
        };
        assert_eq!(
            loaded, want,
            "#1368: a crash at {} must recover one consistent state \
             (roster member, TreeKEM epoch); old={old:?} new={new:?}",
            image.barrier
        );
        assert!(
            journals_left(image, &fixture.group_id).is_empty(),
            "#1368: the restart at {} consumes both journals: {:?}",
            image.barrier,
            journals_left(image, &fixture.group_id)
        );
    }
    Ok(())
}

#[tokio::test]
async fn issue1368_rebind_crash_at_each_barrier_recovers_one_state() -> Result<()> {
    let fixture = rebind_fixture(0x69).await?;
    let old_name = fixture
        .state
        .named_groups
        .read()
        .await
        .get(&fixture.group_id)
        .map(|info| info.name.clone())
        .context("fixture record")?;
    let new_name = "issue1368 renamed";
    let armed = Armed::new(&fixture.state)?;
    let status = rename_via_api(&fixture, new_name).await;
    let images = armed.take();
    assert_eq!(status, StatusCode::OK, "the unfaulted rename commits");
    assert_barriers(
        &images,
        &[
            "rebind-1-hsjournal",
            "rebind-2-journal",
            "save-1-sidecar",
            "save-2-named",
            "rebind-3-sidecar",
            "rebind-4-snapshot",
            "rebind-5-journal-removed",
            "rebind-6-done",
        ],
    );
    for image in &images {
        let (merged, treekem) = restart_image(&fixture.state, image).await?;
        let record = merged
            .get(&fixture.group_id)
            .context("the group record survives the crash")?;
        // Before the commit point the old name, from it on the new one.
        let want = if image.barrier == "rebind-1-hsjournal" {
            old_name.as_str()
        } else {
            new_name
        };
        assert_eq!(
            record.name, want,
            "#1368: a crash at {} must recover one consistent record",
            image.barrier
        );
        assert!(
            treekem.contains_key(&fixture.group_id),
            "#1368: a crash at {} must keep the TreeKEM group restorable",
            image.barrier
        );
        assert!(
            journals_left(image, &fixture.group_id).is_empty(),
            "#1368: the restart at {} consumes both journals: {:?}",
            image.barrier,
            journals_left(image, &fixture.group_id)
        );
    }
    Ok(())
}
