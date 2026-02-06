//! TaskList CRDT bindings for Python.
//!
//! This module provides Python bindings for x0x's CRDT-based task lists,
//! enabling collaborative task management across agents.

use pyo3::prelude::*;
use pyo3::types::PyType;
use pyo3_asyncio::tokio::future_into_py;

/// A unique identifier for a task in a task list.
///
/// TaskIds are 32-byte values (displayed as 64-character hex strings)
/// that uniquely identify tasks across the distributed system.
///
/// # Example (Python)
///
/// ```python
/// task_id = TaskId.from_hex("a" * 64)
/// print(task_id.to_hex())
/// ```
#[pyclass]
#[derive(Clone)]
pub struct TaskId {
    inner: x0x::crdt::TaskId,
}

#[pymethods]
impl TaskId {
    /// Create a TaskId from a hex-encoded string.
    ///
    /// # Arguments
    ///
    /// * `hex_str` - 64-character hex string (32 bytes)
    ///
    /// # Raises
    ///
    /// ValueError: If the hex string is invalid or wrong length
    #[classmethod]
    fn from_hex(_cls: &PyType, hex_str: &str) -> PyResult<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid hex string: {}", e))
        })?;

        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "TaskId must be 32 bytes (64 hex chars)",
            )
        })?;

        Ok(TaskId {
            inner: x0x::crdt::TaskId::from_bytes(bytes),
        })
    }

    /// Convert this TaskId to a hex-encoded string.
    ///
    /// # Returns
    ///
    /// 64-character hex string
    fn to_hex(&self) -> String {
        hex::encode(self.inner.as_bytes())
    }

    /// String representation (hex-encoded).
    fn __str__(&self) -> String {
        self.to_hex()
    }

    /// Debug representation.
    fn __repr__(&self) -> String {
        format!("TaskId('{}')", self.to_hex())
    }

    /// Hash for use in dicts/sets.
    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.inner.as_bytes().hash(&mut hasher);
        hasher.finish()
    }

    /// Equality comparison.
    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

/// A snapshot of a task's current state.
///
/// TaskItem represents a task at a point in time with its metadata,
/// status, and assignee information.
///
/// # Example (Python)
///
/// ```python
/// tasks = await task_list.list_tasks()
/// for task in tasks:
///     print(f"[{task.status}] {task.title}")
///     if task.assignee:
///         print(f"  Assigned to: {task.assignee}")
/// ```
#[pyclass]
#[derive(Clone)]
pub struct TaskItem {
    /// Task ID (hex-encoded).
    #[pyo3(get)]
    pub id: String,

    /// Task title.
    #[pyo3(get)]
    pub title: String,

    /// Task description.
    #[pyo3(get)]
    pub description: String,

    /// Checkbox state: "empty", "claimed", or "done".
    #[pyo3(get)]
    pub status: String,

    /// Agent ID of assignee (hex-encoded) if claimed or done.
    #[pyo3(get)]
    pub assignee: Option<String>,

    /// Display priority (0-255, higher = more important).
    #[pyo3(get)]
    pub priority: u32,
}

#[pymethods]
impl TaskItem {
    /// String representation showing task status and title.
    fn __repr__(&self) -> String {
        format!(
            "TaskItem(id='{}...', title='{}', status='{}')",
            &self.id[..8],
            self.title,
            self.status
        )
    }

    /// String representation for display.
    fn __str__(&self) -> String {
        format!("[{}] {}", self.status, self.title)
    }
}

impl TaskItem {
    /// Convert from x0x::TaskSnapshot to Python TaskItem.
    fn from_snapshot(snapshot: x0x::TaskSnapshot) -> Self {
        let (status, assignee) = match snapshot.state {
            x0x::crdt::CheckboxState::Empty => ("empty".to_string(), None),
            x0x::crdt::CheckboxState::Claimed { agent_id, .. } => (
                "claimed".to_string(),
                Some(hex::encode(agent_id.as_bytes())),
            ),
            x0x::crdt::CheckboxState::Done { agent_id, .. } => {
                ("done".to_string(), Some(hex::encode(agent_id.as_bytes())))
            }
        };

        TaskItem {
            id: snapshot.id.to_string(),
            title: snapshot.title,
            description: snapshot.description,
            status,
            assignee,
            priority: snapshot.priority as u32,
        }
    }
}

/// A handle to a collaborative task list.
///
/// TaskList provides CRDT-based task management with automatic
/// synchronization across agents via the gossip network.
///
/// Each task has three checkbox states:
/// - [ ] Empty: Available to be claimed
/// - [-] Claimed: Assigned to an agent
/// - [x] Done: Completed
///
/// # Example (Python)
///
/// ```python
/// # Add a task
/// task_id = await task_list.add_task("Fix bug", "Network timeout issue")
///
/// # Claim it
/// await task_list.claim_task(task_id)
///
/// # Complete it
/// await task_list.complete_task(task_id)
///
/// # List all tasks
/// tasks = await task_list.list_tasks()
/// ```
#[pyclass]
pub struct TaskList {
    inner: x0x::TaskListHandle,
}

#[pymethods]
impl TaskList {
    /// Add a new task to the list.
    ///
    /// The task starts in the Empty state and can be claimed by any agent.
    ///
    /// # Arguments
    ///
    /// * `title` - Task title (e.g., "Implement feature X")
    /// * `description` - Optional detailed description of the task
    ///
    /// # Returns
    ///
    /// Task ID as a hex-encoded string
    ///
    /// # Raises
    ///
    /// RuntimeError: If the operation fails
    ///
    /// # Example (Python)
    ///
    /// ```python
    /// task_id = await task_list.add_task(
    ///     "Fix bug in network layer",
    ///     "The connection timeout is too aggressive"
    /// )
    /// print(f"Created task: {task_id}")
    /// ```
    fn add_task<'a>(
        &'a self,
        py: Python<'a>,
        title: String,
        description: Option<String>,
    ) -> PyResult<&'a PyAny> {
        let description = description.unwrap_or_default();
        let handle = self.inner.clone();

        future_into_py(py, async move {
            let task_id = handle.add_task(title, description).await.map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to add task: {}",
                    e
                ))
            })?;

            Ok(task_id.to_string())
        })
    }

    /// Claim a task for the current agent.
    ///
    /// Changes the task state from Empty [ ] to Claimed [-] and assigns
    /// it to the agent associated with this task list. If multiple agents
    /// claim simultaneously, the CRDT resolves the conflict deterministically.
    ///
    /// # Arguments
    ///
    /// * `task_id` - ID of the task to claim (hex-encoded string)
    ///
    /// # Raises
    ///
    /// ValueError: If task_id is invalid hex
    /// RuntimeError: If the operation fails
    ///
    /// # Example (Python)
    ///
    /// ```python
    /// await task_list.claim_task(task_id)
    /// ```
    fn claim_task<'a>(&'a self, py: Python<'a>, task_id: String) -> PyResult<&'a PyAny> {
        let bytes = hex::decode(&task_id).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid task ID hex: {}", e))
        })?;

        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>("Task ID must be 32 bytes")
        })?;

        let task_id = x0x::crdt::TaskId::from_bytes(bytes);
        let handle = self.inner.clone();

        future_into_py(py, async move {
            handle.claim_task(task_id).await.map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to claim task: {}",
                    e
                ))
            })?;

            Ok(())
        })
    }

    /// Mark a task as complete.
    ///
    /// Changes the task state to Done [x]. The CRDT ensures only valid
    /// state transitions are applied.
    ///
    /// # Arguments
    ///
    /// * `task_id` - ID of the task to complete (hex-encoded string)
    ///
    /// # Raises
    ///
    /// ValueError: If task_id is invalid hex
    /// RuntimeError: If the operation fails
    ///
    /// # Example (Python)
    ///
    /// ```python
    /// await task_list.complete_task(task_id)
    /// ```
    fn complete_task<'a>(&'a self, py: Python<'a>, task_id: String) -> PyResult<&'a PyAny> {
        let bytes = hex::decode(&task_id).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid task ID hex: {}", e))
        })?;

        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>("Task ID must be 32 bytes")
        })?;

        let task_id = x0x::crdt::TaskId::from_bytes(bytes);
        let handle = self.inner.clone();

        future_into_py(py, async move {
            handle.complete_task(task_id).await.map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to complete task: {}",
                    e
                ))
            })?;

            Ok(())
        })
    }

    /// Get a snapshot of all tasks in the list.
    ///
    /// Returns the current state of all tasks with their metadata.
    ///
    /// # Returns
    ///
    /// List of TaskItem objects
    ///
    /// # Raises
    ///
    /// RuntimeError: If the operation fails
    ///
    /// # Example (Python)
    ///
    /// ```python
    /// tasks = await task_list.list_tasks()
    /// for task in tasks:
    ///     print(f"[{task.status}] {task.title}")
    /// ```
    fn list_tasks<'a>(&'a self, py: Python<'a>) -> PyResult<&'a PyAny> {
        let handle = self.inner.clone();

        future_into_py(py, async move {
            let snapshots = handle.list_tasks().await.map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to list tasks: {}",
                    e
                ))
            })?;

            let items: Vec<TaskItem> = snapshots.into_iter().map(TaskItem::from_snapshot).collect();

            Ok(items)
        })
    }

    /// Reorder tasks in the list.
    ///
    /// Changes the display order of tasks. The CRDT uses Last-Write-Wins
    /// semantics for ordering.
    ///
    /// # Arguments
    ///
    /// * `task_ids` - List of task IDs in the desired order (hex strings)
    ///
    /// # Raises
    ///
    /// ValueError: If any task_id is invalid hex
    /// RuntimeError: If the operation fails
    ///
    /// # Example (Python)
    ///
    /// ```python
    /// await task_list.reorder([task_id1, task_id2, task_id3])
    /// ```
    fn reorder<'a>(&'a self, py: Python<'a>, task_ids: Vec<String>) -> PyResult<&'a PyAny> {
        let mut task_id_list = Vec::with_capacity(task_ids.len());

        for id in task_ids {
            let bytes = hex::decode(&id).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid task ID hex: {}",
                    e
                ))
            })?;

            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>("Task ID must be 32 bytes")
            })?;

            task_id_list.push(x0x::crdt::TaskId::from_bytes(bytes));
        }

        let handle = self.inner.clone();

        future_into_py(py, async move {
            handle.reorder(task_id_list).await.map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to reorder: {}",
                    e
                ))
            })?;

            Ok(())
        })
    }
}

impl TaskList {
    /// Internal constructor from Rust TaskListHandle.
    ///
    /// This is used by the Agent bindings when creating task lists.
    #[allow(dead_code)]
    pub(crate) fn from_handle(handle: x0x::TaskListHandle) -> Self {
        TaskList { inner: handle }
    }
}
