use napi::bindgen_prelude::*;
use napi_derive::napi;

/// A handle to a collaborative task list.
///
/// TaskList provides CRDT-based task management with automatic
/// synchronization across agents via the gossip network.
///
/// Each task has three checkbox states:
/// - [ ] Empty: Available to be claimed
/// - [-] Claimed: Assigned to an agent
/// - [x] Done: Completed
#[napi]
pub struct TaskList {
    inner: x0x::TaskListHandle,
}

#[napi]
impl TaskList {
    /// Add a new task to the list.
    ///
    /// The task starts in the Empty state and can be claimed by any agent.
    ///
    /// # Arguments
    ///
    /// * `title` - Task title (e.g., "Implement feature X")
    /// * `description` - Detailed description of the task
    ///
    /// # Returns
    ///
    /// Promise resolving to the task ID (hex-encoded string)
    ///
    /// # Example (JavaScript)
    ///
    /// ```javascript
    /// const taskId = await taskList.addTask(
    ///   "Fix bug in network layer",
    ///   "The connection timeout is too aggressive"
    /// );
    /// console.log(`Created task: ${taskId}`);
    /// ```
    #[napi]
    pub async fn add_task(&self, title: String, description: String) -> Result<String> {
        let task_id = self.inner.add_task(title, description).await.map_err(|e| {
            Error::new(Status::GenericFailure, format!("Failed to add task: {}", e))
        })?;

        Ok(task_id.to_string())
    }

    /// Claim a task for yourself.
    ///
    /// Changes the task state from Empty [ ] to Claimed [-] and assigns
    /// it to your agent ID. If multiple agents claim simultaneously, the
    /// CRDT resolves the conflict deterministically.
    ///
    /// # Arguments
    ///
    /// * `task_id` - ID of the task to claim (hex-encoded string)
    ///
    /// # Returns
    ///
    /// Promise that resolves when the claim is applied locally
    ///
    /// # Example (JavaScript)
    ///
    /// ```javascript
    /// await taskList.claimTask(taskId);
    /// console.log("Task claimed!");
    /// ```
    #[napi]
    pub async fn claim_task(&self, task_id: String) -> Result<()> {
        let bytes = hex::decode(&task_id)
            .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid task ID hex: {}", e)))?;
        let task_id = x0x::crdt::TaskId::from_bytes(
            bytes.try_into().map_err(|_| Error::new(Status::InvalidArg, "Task ID must be 32 bytes"))?
        );

        self.inner.claim_task(task_id).await.map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to claim task: {}", e),
            )
        })
    }

    /// Mark a task as complete.
    ///
    /// Changes the task state to Done [x]. Only the agent that claimed
    /// the task can complete it (enforced by CRDT rules).
    ///
    /// # Arguments
    ///
    /// * `task_id` - ID of the task to complete (hex-encoded string)
    ///
    /// # Returns
    ///
    /// Promise that resolves when the completion is applied locally
    ///
    /// # Example (JavaScript)
    ///
    /// ```javascript
    /// await taskList.completeTask(taskId);
    /// console.log("Task completed!");
    /// ```
    #[napi]
    pub async fn complete_task(&self, task_id: String) -> Result<()> {
        let bytes = hex::decode(&task_id)
            .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid task ID hex: {}", e)))?;
        let task_id = x0x::crdt::TaskId::from_bytes(
            bytes.try_into().map_err(|_| Error::new(Status::InvalidArg, "Task ID must be 32 bytes"))?
        );

        self.inner.complete_task(task_id).await.map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to complete task: {}", e),
            )
        })
    }

    /// Get a snapshot of all tasks in the list.
    ///
    /// Returns the current state of all tasks with their metadata.
    ///
    /// # Returns
    ///
    /// Promise resolving to an array of `TaskSnapshot` objects
    ///
    /// # Example (JavaScript)
    ///
    /// ```javascript
    /// const tasks = await taskList.listTasks();
    /// for (const task of tasks) {
    ///   console.log(`[${task.state}] ${task.title}`);
    /// }
    /// ```
    #[napi]
    pub async fn list_tasks(&self) -> Result<Vec<TaskSnapshot>> {
        let snapshots = self.inner.list_tasks().await.map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to list tasks: {}", e),
            )
        })?;

        Ok(snapshots.into_iter().map(TaskSnapshot::from_rust).collect())
    }

    /// Reorder tasks in the list.
    ///
    /// Changes the display order of tasks. The CRDT uses Last-Write-Wins
    /// semantics for ordering.
    ///
    /// # Arguments
    ///
    /// * `task_ids` - Array of task IDs in the desired order
    ///
    /// # Returns
    ///
    /// Promise that resolves when the reordering is applied locally
    ///
    /// # Example (JavaScript)
    ///
    /// ```javascript
    /// await taskList.reorder([taskId1, taskId2, taskId3]);
    /// ```
    #[napi]
    pub async fn reorder(&self, task_ids: Vec<String>) -> Result<()> {
        let mut task_id_list = Vec::with_capacity(task_ids.len());
        for id in task_ids {
            let bytes = hex::decode(&id)
                .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid task ID hex: {}", e)))?;
            let bytes: [u8; 32] = bytes.try_into()
                .map_err(|_| Error::new(Status::InvalidArg, "Task ID must be 32 bytes"))?;
            task_id_list.push(x0x::crdt::TaskId::from_bytes(bytes));
        }

        self.inner
            .reorder(task_id_list)
            .await
            .map_err(|e| Error::new(Status::GenericFailure, format!("Failed to reorder: {}", e)))
    }
}

/// A snapshot of a task's current state.
#[napi(object)]
pub struct TaskSnapshot {
    /// Task ID (hex-encoded)
    pub id: String,
    /// Task title
    pub title: String,
    /// Task description
    pub description: String,
    /// Checkbox state: "empty", "claimed", or "done"
    pub state: String,
    /// Agent ID of assignee (if claimed or done)
    pub assignee: Option<String>,
    /// Display priority (0-255, higher = more important)
    pub priority: u32,
}

impl TaskSnapshot {
    fn from_rust(snapshot: x0x::TaskSnapshot) -> Self {
        TaskSnapshot {
            id: snapshot.id.to_string(),
            title: snapshot.title,
            description: snapshot.description,
            state: match snapshot.state {
                x0x::crdt::CheckboxState::Empty => "empty".to_string(),
                x0x::crdt::CheckboxState::Claimed { .. } => "claimed".to_string(),
                x0x::crdt::CheckboxState::Done { .. } => "done".to_string(),
            },
            assignee: match snapshot.state {
                x0x::crdt::CheckboxState::Claimed { agent_id, .. }
                | x0x::crdt::CheckboxState::Done { agent_id, .. } => {
                    Some(hex::encode(agent_id.as_bytes()))
                }
                x0x::crdt::CheckboxState::Empty => None,
            },
            priority: snapshot.priority as u32,
        }
    }
}

#[allow(dead_code)]
impl TaskList {
    /// Internal constructor from Rust TaskListHandle
    pub(crate) fn from_handle(handle: x0x::TaskListHandle) -> Self {
        TaskList { inner: handle }
    }
}
