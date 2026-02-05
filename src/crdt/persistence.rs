//! Persistent storage for task lists.
//!
//! Provides local storage for `TaskList` instances with atomic writes,
//! automatic directory creation, and graceful error handling for corrupted files.

use crate::crdt::{TaskList, TaskListId};
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
        // Ensure directory exists
        fs::create_dir_all(&self.storage_path).await?;

        // Serialize task list
        let serialized =
            bincode::serialize(task_list).map_err(crate::crdt::error::CrdtError::Serialization)?;

        // Write to temporary file
        let file_path = self.list_file_path(list_id);
        let temp_path = file_path.with_extension("tmp");

        fs::write(&temp_path, &serialized).await?;

        // Atomically rename temp file to final location
        fs::rename(&temp_path, &file_path).await?;

        Ok(())
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
    /// - File is corrupted (invalid bincode)
    /// - I/O operations fail
    pub async fn load_task_list(
        &self,
        list_id: &TaskListId,
    ) -> crate::crdt::error::Result<TaskList> {
        let file_path = self.list_file_path(list_id);

        let serialized = fs::read(&file_path).await?;

        bincode::deserialize(&serialized)
            .map_err(crate::crdt::error::CrdtError::Serialization)
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
        // Create directory if it doesn't exist yet (no task lists to list)
        if !self.storage_path.exists() {
            return Ok(Vec::new());
        }

        let mut dir_entries = fs::read_dir(&self.storage_path).await?;

        let mut list_ids = Vec::new();

        while let Some(entry) = dir_entries.next_entry().await? {
            let path = entry.path();

            // Skip temporary files (from failed writes)
            if path.extension().is_some_and(|ext| ext == "tmp") {
                continue;
            }

            // Only process .bin files
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
    pub async fn delete_task_list(
        &self,
        list_id: &TaskListId,
    ) -> crate::crdt::error::Result<()> {
        let file_path = self.list_file_path(list_id);

        fs::remove_file(file_path).await?;

        Ok(())
    }

    /// Get the file path for a task list by its ID.
    fn list_file_path(&self, list_id: &TaskListId) -> PathBuf {
        self.storage_path.join(format!("{}.bin", list_id))
    }
}

// Module-level tests kept simple to avoid type conflicts between
// ant_quic::PeerId and saorsa_gossip_types::PeerId
// Full integration tests are in tests/ directory
