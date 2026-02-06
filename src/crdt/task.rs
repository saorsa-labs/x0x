//! Task identifier and metadata types for CRDT task lists.

use crate::identity::AgentId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Task identifier derived from BLAKE3 hash.
///
/// TaskId is content-addressed: derived from BLAKE3(title || creator || timestamp).
/// This ensures:
/// - Unique IDs for different tasks
/// - Reproducible IDs from task content
/// - Collision resistance (BLAKE3 provides 256-bit security)
///
/// # Example
///
/// ```ignore
/// use x0x::crdt::TaskId;
/// use x0x::identity::AgentId;
///
/// let agent_id = AgentId([1u8; 32]);
/// let task_id = TaskId::new("Implement feature X", &agent_id, 1234567890);
/// println!("Task ID: {}", task_id);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskId([u8; 32]);

impl TaskId {
    /// Create a new TaskId from task content.
    ///
    /// The ID is deterministically derived from BLAKE3(title || creator || timestamp).
    /// This makes TaskIds content-addressed and reproducible.
    ///
    /// # Arguments
    ///
    /// * `title` - The task title
    /// * `creator` - The agent who created the task
    /// * `timestamp` - Creation timestamp (Unix milliseconds)
    ///
    /// # Returns
    ///
    /// A unique TaskId for this task.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let agent = AgentId([1u8; 32]);
    /// let id1 = TaskId::new("Same title", &agent, 1000);
    /// let id2 = TaskId::new("Same title", &agent, 1000);
    /// assert_eq!(id1, id2); // Same inputs = same ID
    ///
    /// let id3 = TaskId::new("Different title", &agent, 1000);
    /// assert_ne!(id1, id3); // Different inputs = different ID
    /// ```
    #[must_use]
    pub fn new(title: &str, creator: &AgentId, timestamp: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(title.as_bytes());
        hasher.update(creator.as_bytes());
        hasher.update(&timestamp.to_le_bytes());
        let hash = hasher.finalize();
        Self(*hash.as_bytes())
    }

    /// Get the raw 32-byte representation of this TaskId.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create a TaskId from raw bytes.
    ///
    /// Use this when deserializing TaskIds from storage or network.
    ///
    /// # Arguments
    ///
    /// * `bytes` - 32-byte array
    ///
    /// # Returns
    ///
    /// A TaskId wrapping the provided bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a TaskId from a hex-encoded string.
    ///
    /// # Arguments
    ///
    /// * `s` - Hex-encoded string (64 characters)
    ///
    /// # Returns
    ///
    /// A TaskId if parsing succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not valid hex or not 64 characters.
    pub fn from_string(s: &str) -> Result<Self, String> {
        if s.len() != 64 {
            return Err(format!(
                "Invalid TaskId length: expected 64 hex chars, got {}",
                s.len()
            ));
        }

        let bytes = hex::decode(s).map_err(|e| format!("Invalid hex encoding: {}", e))?;

        if bytes.len() != 32 {
            return Err(format!(
                "Invalid TaskId bytes: expected 32 bytes, got {}",
                bytes.len()
            ));
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Metadata for a task item.
///
/// Contains all the descriptive information about a task that can be
/// updated after creation. The actual checkbox state is managed separately
/// in the TaskItem CRDT.
///
/// # Example
///
/// ```ignore
/// use x0x::crdt::TaskMetadata;
/// use x0x::identity::AgentId;
///
/// let agent = AgentId([1u8; 32]);
/// let metadata = TaskMetadata {
///     title: "Implement feature X".to_string(),
///     description: "Add support for Y in module Z".to_string(),
///     priority: 128,
///     created_by: agent,
///     created_at: 1234567890,
///     tags: vec!["backend".to_string(), "api".to_string()],
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskMetadata {
    /// The task title (short summary).
    pub title: String,

    /// The task description (detailed explanation).
    pub description: String,

    /// Task priority (0-255, higher = more important).
    ///
    /// Suggested values:
    /// - 255: Critical/Urgent
    /// - 192: High priority
    /// - 128: Normal priority (default)
    /// - 64: Low priority
    /// - 0: Minimal priority
    pub priority: u8,

    /// The agent who created this task.
    pub created_by: AgentId,

    /// When this task was created (Unix timestamp in milliseconds).
    pub created_at: u64,

    /// Tags for categorizing tasks.
    ///
    /// Examples: ["backend", "frontend", "bug", "feature", "docs"]
    pub tags: Vec<String>,
}

impl TaskMetadata {
    /// Create new task metadata.
    ///
    /// # Arguments
    ///
    /// * `title` - Task title
    /// * `description` - Task description
    /// * `priority` - Priority level (0-255)
    /// * `created_by` - Creator's agent ID
    /// * `created_at` - Creation timestamp
    ///
    /// # Returns
    ///
    /// A new TaskMetadata instance.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let agent = AgentId([1u8; 32]);
    /// let metadata = TaskMetadata::new(
    ///     "Add tests",
    ///     "Write unit tests for parser module",
    ///     128,
    ///     agent,
    ///     1234567890,
    /// );
    /// ```
    #[must_use]
    pub fn new(
        title: impl Into<String>,
        description: impl Into<String>,
        priority: u8,
        created_by: AgentId,
        created_at: u64,
    ) -> Self {
        Self {
            title: title.into(),
            description: description.into(),
            priority,
            created_by,
            created_at,
            tags: Vec::new(),
        }
    }

    /// Create metadata with default priority (128).
    ///
    /// # Arguments
    ///
    /// * `title` - Task title
    /// * `description` - Task description
    /// * `created_by` - Creator's agent ID
    /// * `created_at` - Creation timestamp
    ///
    /// # Returns
    ///
    /// A new TaskMetadata instance with priority=128.
    #[must_use]
    pub fn with_default_priority(
        title: impl Into<String>,
        description: impl Into<String>,
        created_by: AgentId,
        created_at: u64,
    ) -> Self {
        Self::new(title, description, 128, created_by, created_at)
    }

    /// Add a tag to this task.
    ///
    /// # Arguments
    ///
    /// * `tag` - Tag to add
    ///
    /// # Returns
    ///
    /// Self for chaining.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Add multiple tags to this task.
    ///
    /// # Arguments
    ///
    /// * `tags` - Iterator of tags to add
    ///
    /// # Returns
    ///
    /// Self for chaining.
    pub fn with_tags<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.tags.extend(tags.into_iter().map(|t| t.into()));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    #[test]
    fn test_task_id_deterministic() {
        let agent = agent(1);
        let title = "Test task";
        let timestamp = 1000;

        let id1 = TaskId::new(title, &agent, timestamp);
        let id2 = TaskId::new(title, &agent, timestamp);

        assert_eq!(id1, id2, "Same inputs should produce same TaskId");
    }

    #[test]
    fn test_task_id_different_titles() {
        let agent = agent(1);
        let timestamp = 1000;

        let id1 = TaskId::new("Title A", &agent, timestamp);
        let id2 = TaskId::new("Title B", &agent, timestamp);

        assert_ne!(id1, id2, "Different titles should produce different IDs");
    }

    #[test]
    fn test_task_id_different_creators() {
        let agent1 = agent(1);
        let agent2 = agent(2);
        let title = "Same title";
        let timestamp = 1000;

        let id1 = TaskId::new(title, &agent1, timestamp);
        let id2 = TaskId::new(title, &agent2, timestamp);

        assert_ne!(id1, id2, "Different creators should produce different IDs");
    }

    #[test]
    fn test_task_id_different_timestamps() {
        let agent = agent(1);
        let title = "Same title";

        let id1 = TaskId::new(title, &agent, 1000);
        let id2 = TaskId::new(title, &agent, 2000);

        assert_ne!(
            id1, id2,
            "Different timestamps should produce different IDs"
        );
    }

    #[test]
    fn test_task_id_as_bytes() {
        let agent = agent(1);
        let id = TaskId::new("Test", &agent, 1000);
        let bytes = id.as_bytes();

        assert_eq!(bytes.len(), 32, "TaskId should be 32 bytes");
    }

    #[test]
    fn test_task_id_from_bytes() {
        let original_bytes = [42u8; 32];
        let id = TaskId::from_bytes(original_bytes);

        assert_eq!(id.as_bytes(), &original_bytes);
    }

    #[test]
    fn test_task_id_display() {
        let agent = agent(1);
        let id = TaskId::new("Test", &agent, 1000);
        let display = format!("{}", id);

        // Should be 64 hex characters (32 bytes * 2)
        assert_eq!(display.len(), 64);
        // Should only contain hex characters
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_task_id_serialization() {
        let agent = agent(1);
        let id = TaskId::new("Test", &agent, 1000);

        let serialized = bincode::serialize(&id).ok().unwrap();
        let deserialized: TaskId = bincode::deserialize(&serialized).ok().unwrap();

        assert_eq!(id, deserialized);
    }

    #[test]
    fn test_task_metadata_new() {
        let agent = agent(1);
        let metadata = TaskMetadata::new("Title", "Description", 200, agent, 1234567890);

        assert_eq!(metadata.title, "Title");
        assert_eq!(metadata.description, "Description");
        assert_eq!(metadata.priority, 200);
        assert_eq!(metadata.created_by, agent);
        assert_eq!(metadata.created_at, 1234567890);
        assert!(metadata.tags.is_empty());
    }

    #[test]
    fn test_task_metadata_default_priority() {
        let agent = agent(1);
        let metadata =
            TaskMetadata::with_default_priority("Title", "Description", agent, 1234567890);

        assert_eq!(metadata.priority, 128);
    }

    #[test]
    fn test_task_metadata_with_tag() {
        let agent = agent(1);
        let metadata = TaskMetadata::new("Title", "Desc", 128, agent, 1000).with_tag("backend");

        assert_eq!(metadata.tags.len(), 1);
        assert_eq!(metadata.tags[0], "backend");
    }

    #[test]
    fn test_task_metadata_with_tags() {
        let agent = agent(1);
        let metadata = TaskMetadata::new("Title", "Desc", 128, agent, 1000)
            .with_tags(vec!["backend", "api", "feature"]);

        assert_eq!(metadata.tags.len(), 3);
        assert_eq!(metadata.tags[0], "backend");
        assert_eq!(metadata.tags[1], "api");
        assert_eq!(metadata.tags[2], "feature");
    }

    #[test]
    fn test_task_metadata_chaining() {
        let agent = agent(1);
        let metadata = TaskMetadata::new("Title", "Desc", 128, agent, 1000)
            .with_tag("backend")
            .with_tag("urgent")
            .with_tags(vec!["api", "feature"]);

        assert_eq!(metadata.tags.len(), 4);
        assert_eq!(metadata.tags, vec!["backend", "urgent", "api", "feature"]);
    }

    #[test]
    fn test_task_metadata_serialization() {
        let agent = agent(1);
        let metadata = TaskMetadata::new("Title", "Description", 200, agent, 1234567890)
            .with_tags(vec!["tag1", "tag2"]);

        let serialized = bincode::serialize(&metadata).ok().unwrap();
        let deserialized: TaskMetadata = bincode::deserialize(&serialized).ok().unwrap();

        assert_eq!(metadata, deserialized);
    }

    #[test]
    fn test_task_metadata_equality() {
        let agent = agent(1);

        let meta1 = TaskMetadata::new("Title", "Desc", 128, agent, 1000).with_tag("test");

        let meta2 = TaskMetadata::new("Title", "Desc", 128, agent, 1000).with_tag("test");

        assert_eq!(meta1, meta2);
    }

    #[test]
    fn test_task_metadata_inequality_different_title() {
        let agent = agent(1);

        let meta1 = TaskMetadata::new("Title A", "Desc", 128, agent, 1000);
        let meta2 = TaskMetadata::new("Title B", "Desc", 128, agent, 1000);

        assert_ne!(meta1, meta2);
    }

    #[test]
    fn test_task_metadata_inequality_different_tags() {
        let agent = agent(1);

        let meta1 = TaskMetadata::new("Title", "Desc", 128, agent, 1000).with_tag("tag1");

        let meta2 = TaskMetadata::new("Title", "Desc", 128, agent, 1000).with_tag("tag2");

        assert_ne!(meta1, meta2);
    }
}
