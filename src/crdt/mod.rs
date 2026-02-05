//! CRDT-based collaborative task lists for x0x agents.
//!
//! This module provides conflict-free replicated data types (CRDTs) for
//! building collaborative task lists that agents can share and synchronize
//! through the gossip network.
//!
//! ## Key Components
//!
//! - [`error`]: Error types for CRDT operations
//!
//! ## Usage
//!
//! ```ignore
//! use x0x::crdt::{TaskList, TaskItem};
//!
//! // Create a new task list
//! let mut task_list = TaskList::new(list_id, "Sprint Planning", peer_id);
//!
//! // Add a task
//! let task = TaskItem::new(task_id, metadata, peer_id);
//! task_list.add_task(task, peer_id, seq)?;
//!
//! // Claim a task
//! task_list.claim_task(&task_id, agent_id, peer_id, seq)?;
//!
//! // Complete a task
//! task_list.complete_task(&task_id, agent_id, peer_id, seq)?;
//! ```

pub mod checkbox;
pub mod delta;
pub mod error;
pub mod persistence;
pub mod sync;
pub mod task;
pub mod task_item;
pub mod task_list;

// Re-export commonly used types
pub use checkbox::{CheckboxError, CheckboxState};
pub use delta::TaskListDelta;
pub use error::{CrdtError, Result};
pub use persistence::TaskListStorage;
pub use sync::TaskListSync;
pub use task::{TaskId, TaskMetadata};
pub use task_item::TaskItem;
pub use task_list::{TaskList, TaskListId};
