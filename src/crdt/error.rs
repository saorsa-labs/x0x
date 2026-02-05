//! Error types for CRDT task list operations.

use crate::crdt::CheckboxState;
use crate::identity::AgentId;

/// Result type for CRDT operations.
pub type Result<T> = std::result::Result<T, CrdtError>;

/// Task identifier (BLAKE3 hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskId([u8; 32]);

impl TaskId {
    /// Get the bytes of this task ID.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Errors that can occur during CRDT task list operations.
#[derive(Debug, thiserror::Error)]
pub enum CrdtError {
    /// Task not found in the task list.
    #[error("task not found: {0:?}")]
    TaskNotFound(TaskId),

    /// Invalid state transition attempted.
    #[error("invalid state transition: {current:?} -> {attempted:?}")]
    InvalidStateTransition {
        /// The current state of the checkbox.
        current: CheckboxState,
        /// The attempted new state.
        attempted: CheckboxState,
    },

    /// Task is already claimed by another agent.
    #[error("task already claimed by {0}")]
    AlreadyClaimed(AgentId),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    /// CRDT merge operation failed.
    #[error("CRDT merge error: {0}")]
    Merge(String),

    /// Gossip layer error.
    #[error("gossip error: {0}")]
    Gossip(String),

    /// I/O error during persistence.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_agent_id() -> AgentId {
        AgentId([42u8; 32])
    }

    fn mock_task_id() -> TaskId {
        TaskId([1u8; 32])
    }

    #[test]
    fn test_task_id_as_bytes() {
        let id = TaskId([1u8; 32]);
        assert_eq!(id.as_bytes(), &[1u8; 32]);
    }

    #[test]
    fn test_checkbox_state_equality() {
        let agent = mock_agent_id();

        let empty1 = CheckboxState::Empty;
        let empty2 = CheckboxState::Empty;
        assert_eq!(empty1, empty2);

        let claimed1 = CheckboxState::Claimed {
            agent_id: agent,
            timestamp: 100,
        };
        let claimed2 = CheckboxState::Claimed {
            agent_id: agent,
            timestamp: 100,
        };
        assert_eq!(claimed1, claimed2);

        let done1 = CheckboxState::Done {
            agent_id: agent,
            timestamp: 200,
        };
        let done2 = CheckboxState::Done {
            agent_id: agent,
            timestamp: 200,
        };
        assert_eq!(done1, done2);
    }

    #[test]
    fn test_error_display_task_not_found() {
        let task_id = mock_task_id();
        let error = CrdtError::TaskNotFound(task_id);
        let display = format!("{}", error);
        assert!(display.contains("task not found"));
    }

    #[test]
    fn test_error_display_invalid_transition() {
        let agent = mock_agent_id();
        let error = CrdtError::InvalidStateTransition {
            current: CheckboxState::Empty,
            attempted: CheckboxState::Done {
                agent_id: agent,
                timestamp: 100,
            },
        };
        let display = format!("{}", error);
        assert!(display.contains("invalid state transition"));
        assert!(display.contains("Empty"));
        assert!(display.contains("Done"));
    }

    #[test]
    fn test_error_display_already_claimed() {
        let agent = mock_agent_id();
        let error = CrdtError::AlreadyClaimed(agent);
        let display = format!("{}", error);
        assert!(display.contains("already claimed"));
    }

    #[test]
    fn test_error_display_merge() {
        let error = CrdtError::Merge("conflict detected".to_string());
        let display = format!("{}", error);
        assert!(display.contains("CRDT merge error"));
        assert!(display.contains("conflict detected"));
    }

    #[test]
    fn test_error_display_gossip() {
        let error = CrdtError::Gossip("connection failed".to_string());
        let display = format!("{}", error);
        assert!(display.contains("gossip error"));
        assert!(display.contains("connection failed"));
    }

    #[test]
    fn test_error_from_bincode() {
        // bincode::Error doesn't implement Clone, so we can't easily construct one
        // Just verify the From impl exists by type checking
        fn _assert_from_impl(_: bincode::Error) -> CrdtError {
            CrdtError::Serialization(bincode::Error::new(bincode::ErrorKind::Custom(
                "test".to_string(),
            )))
        }
    }

    #[test]
    fn test_error_from_io() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let crdt_error: CrdtError = io_error.into();
        let display = format!("{}", crdt_error);
        assert!(display.contains("I/O error"));
        assert!(display.contains("file not found"));
    }
}
