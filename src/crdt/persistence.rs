//! Persistent storage for task lists.
//!
//! Provides local storage for `TaskList` instances with atomic writes,
//! automatic directory creation, and graceful error handling for corrupted files.

use crate::crdt::{TaskId, TaskList, TaskListId};
use std::path::PathBuf;
use tokio::fs;

/// Storage backend for task lists with atomic writes and error recovery.
///
/// Stores task lists as bincode-serialized files in a local directory.
/// All operations are atomic to prevent partial writes from crashes.
///
/// # Example
///
/// ```ignore
/// let storage = TaskListStorage::new(PathBuf::from("~/.x0x/task_lists"));
/// let list = storage.load_task_list(&list_id).await?;
/// list.add_task("title", "description")?;
/// storage.save_task_list(&list_id, &list).await?;
/// ```
#[derive(Debug, Clone)]
pub struct TaskListStorage {
    storage_path: PathBuf,
}

impl TaskListStorage {
    /// Create a new storage instance with the given path.
    ///
    /// The directory will be created automatically when first needed.
    ///
    /// # Arguments
    ///
    /// * `storage_path` - Directory path for storing task lists
    #[must_use]
    pub fn new(storage_path: PathBuf) -> Self {
        Self { storage_path }
    }

    /// Save a task list to persistent storage with atomic writes.
    ///
    /// Writes to a temporary file first, then atomically renames it to the
    /// final location to prevent partial writes from crashes.
    ///
    /// # Arguments
    ///
    /// * `list_id` - Unique identifier for the task list
    /// * `task_list` - The task list to save
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Directory creation fails
    /// - Serialization fails
    /// - File I/O operations fail
    pub async fn save_task_list(
        &self,
        list_id: &TaskListId,
        task_list: &TaskList,
    ) -> crate::crdt::error::Result<()> {
        fs::create_dir_all(&self.storage_path).await?;

        let serialized = encode_snapshot(task_list)?;

        write_snapshot_atomic(&self.list_file_path(list_id), &serialized)?;

        Ok(())
    }

    /// Load a task list snapshot, distinguishing "nothing on disk" from
    /// "snapshot present but unusable".
    ///
    /// This is the restore path's contract (mirrors `kv::sync::load_snapshot`):
    /// `Ok(None)` means first run, while ANY `Err` means a snapshot exists
    /// but cannot be trusted — callers MUST fail closed rather than start an
    /// empty replica over it (issue #557: a corrupt or truncated snapshot
    /// must never silently install empty state).
    ///
    /// # Errors
    ///
    /// Returns an error if the file lacks the v1 magic header (corrupt,
    /// foreign, or bare-bincode), holds bincode that does not decode, holds
    /// a task list whose id does not match `list_id` (wrong or tampered
    /// file), or a non-"not found" I/O error occurs.
    pub async fn load_task_list_opt(
        &self,
        list_id: &TaskListId,
    ) -> crate::crdt::error::Result<Option<TaskList>> {
        let file_path = self.list_file_path(list_id);

        let serialized = match fs::read(&file_path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let mut list = decode_snapshot(&serialized)?;

        if list.id() != list_id {
            return Err(crate::crdt::error::CrdtError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "task-list snapshot id mismatch for {list_id}: file holds a different list"
                ),
            )));
        }

        // Fail closed: tampered on-disk state cannot bypass provenance verification.
        let dropped = list.admit_all();
        if dropped > 0 {
            tracing::warn!(
                dropped,
                "purged unauthenticated checkbox elements during persistence load"
            );
        }

        Ok(Some(list))
    }

    /// Load a task list from persistent storage.
    ///
    /// Gracefully handles corrupted files by returning an error rather than panicking.
    ///
    /// # Arguments
    ///
    /// * `list_id` - Unique identifier for the task list
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File doesn't exist
    /// - File lacks the v1 magic header or holds undecodable bincode
    /// - I/O operations fail
    pub async fn load_task_list(
        &self,
        list_id: &TaskListId,
    ) -> crate::crdt::error::Result<TaskList> {
        let file_path = self.list_file_path(list_id);

        let serialized = fs::read(&file_path).await?;

        let mut list = decode_snapshot(&serialized)?;

        // Fail closed: tampered on-disk state cannot bypass provenance verification.
        let dropped = list.admit_all();
        if dropped > 0 {
            tracing::warn!(
                dropped,
                "purged unauthenticated checkbox elements during persistence load"
            );
        }

        Ok(list)
    }

    /// List all stored task lists.
    ///
    /// Scans the storage directory and returns filenames of all stored task lists.
    /// Silently skips corrupted files (`.tmp` files from failed writes).
    ///
    /// # Errors
    ///
    /// Returns an error if directory reading fails.
    pub async fn list_task_lists(&self) -> crate::crdt::error::Result<Vec<String>> {
        if !self.storage_path.exists() {
            return Ok(Vec::new());
        }

        let mut dir_entries = fs::read_dir(&self.storage_path).await?;

        let mut list_ids = Vec::new();

        while let Some(entry) = dir_entries.next_entry().await? {
            let path = entry.path();

            if path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| ext == "tmp" || ext.starts_with("tmp."))
            {
                continue;
            }

            if path.extension().is_some_and(|ext| ext == "bin") {
                if let Some(file_name) = path.file_stem() {
                    if let Some(id_str) = file_name.to_str() {
                        list_ids.push(id_str.to_string());
                    }
                }
            }
        }

        Ok(list_ids)
    }

    /// Delete a task list from persistent storage.
    ///
    /// # Arguments
    ///
    /// * `list_id` - Unique identifier for the task list
    ///
    /// # Errors
    ///
    /// Returns an error if the delete operation fails.
    pub async fn delete_task_list(&self, list_id: &TaskListId) -> crate::crdt::error::Result<()> {
        let file_path = self.list_file_path(list_id);

        fs::remove_file(file_path).await?;

        Ok(())
    }

    fn list_file_path(&self, list_id: &TaskListId) -> PathBuf {
        self.storage_path.join(format!("{}.bin", list_id))
    }
}

/// v1 format: `MAGIC(8) || bincode(SnapshotBody { list, seq_counter })`.
///
/// The envelope carries the OR-Set sequence counter, which is `serde(skip)` on
/// `TaskList`. Without it a restored list re-mints `(peer, seq)` tags and
/// `TaskId`s used before the restart. A file without the magic is rejected,
/// not guessed at.
const SNAPSHOT_MAGIC: &[u8; 8] = b"X0XTLS1\0";

/// v2 format: `MAGIC(8) || bincode(SnapshotBodyV2 { list, seq_counter,
/// known_removed })`.
///
/// Adds the observed-removed evidence so a restart does not forget the
/// holder's deletions. It is not inlined into `TaskList` because the bincode
/// body is positional and that would break v1 decoding. Readers accept both
/// magics; writers emit v2 only when the list carries evidence, so an older
/// binary meets a v2 file only on a replica that recorded a removal.
const SNAPSHOT_MAGIC_V2: &[u8; 8] = b"X0XTLS2\0";

#[derive(serde::Deserialize)]
struct SnapshotBody {
    list: TaskList,
    seq_counter: u64,
}

#[derive(serde::Deserialize)]
struct SnapshotBodyV2 {
    list: TaskList,
    seq_counter: u64,
    /// No `serde(default)`: bincode is positional, so a default could never
    /// engage. The v1/v2 split is the magic prefix, not a missing field.
    known_removed: std::collections::HashSet<TaskId>,
}

#[derive(serde::Serialize)]
struct SnapshotBodyRefV1<'a> {
    list: &'a TaskList,
    seq_counter: u64,
}

#[derive(serde::Serialize)]
struct SnapshotBodyRef<'a> {
    list: &'a TaskList,
    seq_counter: u64,
    known_removed: &'a std::collections::HashSet<TaskId>,
}

fn encode_snapshot(list: &TaskList) -> crate::crdt::error::Result<Vec<u8>> {
    let seq_counter = list.seq_counter_value();
    let (magic, bytes) = if list.known_removed_ids().is_empty() {
        let body = SnapshotBodyRefV1 { list, seq_counter };
        (
            SNAPSHOT_MAGIC,
            bincode::serialize(&body).map_err(crate::crdt::error::CrdtError::Serialization)?,
        )
    } else {
        let body = SnapshotBodyRef {
            list,
            seq_counter,
            known_removed: list.known_removed_ids(),
        };
        (
            SNAPSHOT_MAGIC_V2,
            bincode::serialize(&body).map_err(crate::crdt::error::CrdtError::Serialization)?,
        )
    };
    let mut out = Vec::with_capacity(magic.len() + bytes.len());
    out.extend_from_slice(magic);
    out.extend_from_slice(&bytes);
    Ok(out)
}

/// The restored counter is floored by the list's `version`: remote merges bump
/// `version` without minting local seq, so it can run ahead of the counter.
fn decode_snapshot(bytes: &[u8]) -> crate::crdt::error::Result<TaskList> {
    if let Some(body_bytes) = bytes.strip_prefix(SNAPSHOT_MAGIC_V2.as_slice()) {
        let body: SnapshotBodyV2 = bincode::deserialize(body_bytes)
            .map_err(crate::crdt::error::CrdtError::Serialization)?;
        let mut list = body.list;
        list.record_removed_evidence(body.known_removed);
        list.restore_seq_counter(body.seq_counter.max(list.current_version()));
        return Ok(list);
    }
    let Some(body_bytes) = bytes.strip_prefix(SNAPSHOT_MAGIC.as_slice()) else {
        return Err(crate::crdt::error::CrdtError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unrecognized task-list snapshot format (missing v1/v2 magic) — corrupt or \
             foreign file; refusing to restore with seq-counter amnesia",
        )));
    };
    let body: SnapshotBody =
        bincode::deserialize(body_bytes).map_err(crate::crdt::error::CrdtError::Serialization)?;
    let list = body.list;
    list.restore_seq_counter(body.seq_counter.max(list.current_version()));
    Ok(list)
}

/// Durable atomic file write: unique temp file in the same directory,
/// fsync, rename over the destination, then (Unix) fsync the parent
/// directory so the rename itself survives power loss — the same standard
/// as the kv-store snapshot writer (`kv::sync::write_snapshot_atomic`).
///
/// The temp name is unique (pid + counter), so two concurrent saves of the
/// same list cannot interleave writes into one temp file.
///
/// Platform note: on non-Unix targets the parent-directory fsync is
/// skipped (std cannot fsync a directory handle there); the rename is
/// still atomic, but its durability across power loss is not guaranteed.
fn write_snapshot_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static SNAPSHOT_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let n = SNAPSHOT_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{}.{n}", std::process::id()));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::crdt::task_list::TaskListId;
    use crate::crdt::TaskList;
    use saorsa_gossip_types::PeerId;

    fn test_peer_id() -> PeerId {
        PeerId::new([0xBB; 32])
    }

    fn test_list_id(byte: u8) -> TaskListId {
        TaskListId::new([byte; 32])
    }

    fn create_test_list(id: TaskListId, name: &str) -> TaskList {
        TaskList::new(id, name.to_string(), test_peer_id())
    }

    #[tokio::test]
    async fn load_opt_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        assert!(storage
            .load_task_list_opt(&test_list_id(0x10))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn load_opt_corrupt_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let list_id = test_list_id(0x11);
        std::fs::write(dir.path().join(format!("{list_id}.bin")), b"not bincode").unwrap();
        assert!(storage.load_task_list_opt(&list_id).await.is_err());
    }

    #[tokio::test]
    async fn load_opt_truncated_snapshot_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let list_id = test_list_id(0x12);
        let list = create_test_list(list_id, "trunc");
        storage.save_task_list(&list_id, &list).await.unwrap();
        let path = dir.path().join(format!("{list_id}.bin"));
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
        assert!(storage.load_task_list_opt(&list_id).await.is_err());
    }

    #[tokio::test]
    async fn load_opt_id_mismatch_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let a = test_list_id(0x13);
        let b = test_list_id(0x14);
        let list = create_test_list(a, "imposter");
        let bytes = encode_snapshot(&list).unwrap();
        std::fs::write(dir.path().join(format!("{b}.bin")), bytes).unwrap();
        assert!(storage.load_task_list_opt(&b).await.is_err());
    }

    #[tokio::test]
    async fn snapshot_roundtrip_restores_seq_counter_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let list_id = test_list_id(0x17);
        let list = create_test_list(list_id, "seq-ceiling");
        let _ = list.next_seq();
        let _ = list.next_seq();
        let _ = list.next_seq();
        let counter_before = list.seq_counter_value();
        storage.save_task_list(&list_id, &list).await.unwrap();

        let restored = storage
            .load_task_list_opt(&list_id)
            .await
            .unwrap()
            .expect("snapshot present");
        assert!(
            restored.next_seq() > counter_before,
            "restored seq counter must exceed every pre-restart seq"
        );
    }

    #[tokio::test]
    async fn post_restart_readd_same_title_yields_distinct_task_ids() {
        use crate::crdt::{TaskId, TaskItem, TaskMetadata};
        use crate::identity::AgentId;

        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let list_id = test_list_id(0x18);
        let peer = test_peer_id();
        let agent = AgentId([0xA7; 32]);

        fn add_titled_task(list: &mut TaskList, agent: AgentId, peer: PeerId) -> TaskId {
            let seq = list.next_seq();
            let id = TaskId::new("T", &agent, seq);
            let metadata = TaskMetadata::new("T", "d", 128, agent, seq);
            let task = TaskItem::new(id, metadata, peer);
            list.add_task(task, peer, seq).unwrap();
            id
        }

        let mut list = create_test_list(list_id, "re-add");
        let first = add_titled_task(&mut list, agent, peer);
        storage.save_task_list(&list_id, &list).await.unwrap();

        let mut restored = storage
            .load_task_list_opt(&list_id)
            .await
            .unwrap()
            .expect("snapshot present");
        let second = add_titled_task(&mut restored, agent, peer);

        assert_ne!(
            first, second,
            "post-restart re-add must not mint the pre-restart TaskId"
        );
        assert!(
            restored.get_task(&first).is_some(),
            "pre-restart task survives"
        );
        assert!(
            restored.get_task(&second).is_some(),
            "post-restart task present"
        );
    }

    #[tokio::test]
    async fn load_opt_missing_magic_fails_closed_leaving_memory_untouched() {
        use crate::crdt::error::CrdtError;
        use crate::crdt::{TaskId, TaskItem, TaskMetadata};
        use crate::identity::AgentId;

        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let list_id = test_list_id(0x19);
        let peer = test_peer_id();
        let agent = AgentId([0xA9; 32]);

        let mut list = create_test_list(list_id, "magic-guard");
        let task_id = TaskId::new("must-stay", &agent, 1);
        let metadata = TaskMetadata::new("must-stay", "d", 128, agent, 1);
        list.add_task(TaskItem::new(task_id, metadata, peer), peer, 1)
            .unwrap();
        storage.save_task_list(&list_id, &list).await.unwrap();

        let path = dir.path().join(format!("{list_id}.bin"));
        std::fs::write(&path, bincode::serialize(&list).unwrap()).unwrap();
        let err = storage.load_task_list_opt(&list_id).await.unwrap_err();
        assert!(
            matches!(&err, CrdtError::Io(e) if e.kind() == std::io::ErrorKind::InvalidData),
            "missing magic must be a typed InvalidData error, got: {err:?}"
        );

        std::fs::write(&path, b"X0XTL").unwrap();
        assert!(storage.load_task_list_opt(&list_id).await.is_err());

        assert!(
            list.get_task(&task_id).is_some(),
            "failed load must not disturb the in-memory replica"
        );
    }

    #[tokio::test]
    async fn load_opt_roundtrip_returns_saved_list() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let list_id = test_list_id(0x15);
        let list = create_test_list(list_id, "opt-roundtrip");
        storage.save_task_list(&list_id, &list).await.unwrap();
        let loaded = storage.load_task_list_opt(&list_id).await.unwrap();
        assert_eq!(
            loaded.map(|l| l.name().to_string()),
            Some("opt-roundtrip".into())
        );
    }

    #[tokio::test]
    async fn save_writes_unique_tmp_and_leaves_no_residue() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let list_id = test_list_id(0x16);
        let list = create_test_list(list_id, "tmp-check");
        storage.save_task_list(&list_id, &list).await.unwrap();
        storage.save_task_list(&list_id, &list).await.unwrap();
        let residue: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .is_some_and(|x| x == "tmp" || x.starts_with("tmp."))
            })
            .collect();
        assert!(
            residue.is_empty(),
            "durable writer left tmp residue: {residue:?}"
        );
    }

    #[tokio::test]
    async fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let list_id = test_list_id(0x01);
        let list = create_test_list(list_id, "test-list");

        storage.save_task_list(&list_id, &list).await.unwrap();
        let loaded = storage.load_task_list(&list_id).await.unwrap();

        assert_eq!(loaded.id(), list.id());
        assert_eq!(loaded.name(), "test-list");
    }

    #[tokio::test]
    async fn load_nonexistent_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let list_id = test_list_id(0x02);

        let result = storage.load_task_list(&list_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn list_task_lists_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());

        let lists = storage.list_task_lists().await.unwrap();
        assert!(lists.is_empty());
    }

    #[tokio::test]
    async fn list_task_lists_after_save() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let list_id = test_list_id(0x03);
        let list = create_test_list(list_id, "list-me");

        storage.save_task_list(&list_id, &list).await.unwrap();
        let lists = storage.list_task_lists().await.unwrap();

        assert_eq!(lists.len(), 1);
        assert!(lists[0].contains("03"));
    }

    #[tokio::test]
    async fn delete_task_list_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let list_id = test_list_id(0x04);
        let list = create_test_list(list_id, "delete-me");

        storage.save_task_list(&list_id, &list).await.unwrap();
        storage.delete_task_list(&list_id).await.unwrap();

        let result = storage.load_task_list(&list_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn save_creates_directory_automatically() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested").join("deep");
        let storage = TaskListStorage::new(nested);
        let list_id = test_list_id(0x05);
        let list = create_test_list(list_id, "nested-test");

        storage.save_task_list(&list_id, &list).await.unwrap();
        let loaded = storage.load_task_list(&list_id).await.unwrap();
        assert_eq!(loaded.name(), "nested-test");
    }

    #[tokio::test]
    async fn v2_snapshot_roundtrips_removal_evidence() {
        use crate::crdt::{TaskId, TaskItem, TaskMetadata};
        use crate::identity::AgentId;

        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let list_id = test_list_id(0x21);
        let mut list = create_test_list(list_id, "evidence");

        let agent = AgentId([1; 32]);
        let keeper = TaskId::from_bytes([1; 32]);
        let doomed = TaskId::from_bytes([2; 32]);
        for (i, id) in [keeper, doomed].into_iter().enumerate() {
            let metadata = TaskMetadata::new(format!("t{i}"), "d".to_string(), 128, agent, 1000);
            list.add_task(
                TaskItem::new(id, metadata, test_peer_id()),
                test_peer_id(),
                i as u64 + 1,
            )
            .unwrap();
        }
        list.remove_task(&doomed).unwrap();

        storage.save_task_list(&list_id, &list).await.unwrap();

        let raw = std::fs::read(dir.path().join(format!("{list_id}.bin"))).unwrap();
        assert!(
            raw.starts_with(SNAPSHOT_MAGIC_V2.as_slice()),
            "a list carrying removal evidence persists as v2"
        );
        let loaded = storage.load_task_list(&list_id).await.unwrap();

        let serve = loaded.full_delta();
        assert!(serve.added_tasks.contains_key(&keeper));
        assert!(!serve.added_tasks.contains_key(&doomed));
        assert_eq!(
            serve.removed_tasks.get(&doomed).map(|t| t.len()),
            Some(0),
            "removal evidence must survive the restart (v2 envelope)"
        );
    }

    #[tokio::test]
    async fn v1_snapshot_still_loads_with_empty_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let list_id = test_list_id(0x22);
        let list = create_test_list(list_id, "v1-era");

        let body = bincode::serialize(&(list.clone(), 0u64)).unwrap();
        let mut bytes = SNAPSHOT_MAGIC.as_slice().to_vec();
        bytes.extend_from_slice(&body);
        std::fs::write(dir.path().join(format!("{list_id}.bin")), bytes).unwrap();

        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let loaded = storage.load_task_list(&list_id).await.unwrap();
        assert_eq!(loaded.name(), "v1-era");
        assert!(
            loaded.full_delta().removed_tasks.is_empty(),
            "a v1 snapshot restores with no evidence — safe direction"
        );
    }

    #[tokio::test]
    async fn evidence_free_list_persists_as_v1_bytes() {
        use crate::crdt::{TaskId, TaskItem, TaskMetadata};
        use crate::identity::AgentId;

        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let list_id = test_list_id(0x23);
        let mut list = create_test_list(list_id, "no-evidence");

        let agent = AgentId([1; 32]);
        let metadata = TaskMetadata::new("t".to_string(), "d".to_string(), 128, agent, 1000);
        list.add_task(
            TaskItem::new(TaskId::from_bytes([1; 32]), metadata, test_peer_id()),
            test_peer_id(),
            1,
        )
        .unwrap();

        storage.save_task_list(&list_id, &list).await.unwrap();
        let raw = std::fs::read(dir.path().join(format!("{list_id}.bin"))).unwrap();
        assert!(
            raw.starts_with(SNAPSHOT_MAGIC.as_slice()),
            "an evidence-free list must persist as v1 (v0.42.0-readable)"
        );
        assert!(
            !raw.starts_with(SNAPSHOT_MAGIC_V2.as_slice()),
            "v2 must be reserved for snapshots that carry evidence"
        );

        let loaded = storage.load_task_list(&list_id).await.unwrap();
        assert_eq!(loaded.task_count(), 1);
        assert!(loaded.full_delta().removed_tasks.is_empty());
    }

    #[tokio::test]
    async fn list_skips_tmp_files() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let list_id = test_list_id(0x06);
        let list = create_test_list(list_id, "tmp-skip");

        storage.save_task_list(&list_id, &list).await.unwrap();

        let tmp_path = dir.path().join(format!("{}.tmp", list_id));
        tokio::fs::write(&tmp_path, b"garbage").await.unwrap();

        let lists = storage.list_task_lists().await.unwrap();
        assert_eq!(lists.len(), 1);
    }

    #[tokio::test]
    async fn attested_tasklist_roundtrips_through_disk() {
        use crate::crdt::{TaskId, TaskItem, TaskMetadata};

        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let list_id = test_list_id(0x78);
        let peer = test_peer_id();

        let kp = crate::identity::AgentKeypair::generate().unwrap();
        let agent = kp.agent_id();
        let signing = crate::gossip::SigningContext::from_keypair(&kp);

        let task_id = TaskId::new("persist-me", &agent, 1000);
        let metadata = TaskMetadata::new("persist-me", "d", 128, agent, 1000);
        let mut task = TaskItem::new(task_id, metadata, peer);
        task.claim(list_id, agent, peer, 1, &signing).unwrap();

        let mut list = create_test_list(list_id, "attested");
        list.add_task(task, peer, 1).unwrap();

        storage.save_task_list(&list_id, &list).await.unwrap();
        let loaded = storage.load_task_list(&list_id).await.unwrap();

        let t = loaded.get_task(&task_id).expect("attested task persisted");
        assert!(
            t.current_state().is_claimed(),
            "attested claim survives save/load and the admission gate"
        );
        assert_eq!(
            t.claim_record().map(|(a, _)| a),
            Some(agent),
            "the attested claimant round-trips"
        );
    }

    #[tokio::test]
    async fn multiple_lists_independent() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TaskListStorage::new(dir.path().to_path_buf());
        let id_a = test_list_id(0x0A);
        let id_b = test_list_id(0x0B);
        let list_a = create_test_list(id_a, "list-a");
        let list_b = create_test_list(id_b, "list-b");

        storage.save_task_list(&id_a, &list_a).await.unwrap();
        storage.save_task_list(&id_b, &list_b).await.unwrap();

        let loaded_a = storage.load_task_list(&id_a).await.unwrap();
        let loaded_b = storage.load_task_list(&id_b).await.unwrap();
        assert_eq!(loaded_a.name(), "list-a");
        assert_eq!(loaded_b.name(), "list-b");

        let lists = storage.list_task_lists().await.unwrap();
        assert_eq!(lists.len(), 2);
    }
}
