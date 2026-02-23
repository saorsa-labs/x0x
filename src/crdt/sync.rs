//! Task list synchronization using anti-entropy gossip.
//!
//! This module provides automatic synchronization of TaskLists across peers
//! using saorsa-gossip's anti-entropy mechanism combined with pub/sub.
//!
//! ## Architecture
//!
//! - `TaskListSync` wraps a TaskList in Arc<RwLock<>> for concurrent access
//! - Uses `AntiEntropyManager` for periodic background synchronization
//! - Publishes deltas to a gossip topic when local changes occur
//! - Subscribes to the topic to receive and apply remote deltas
//!
//! This provides eventual consistency across all peers sharing the same topic.

use crate::crdt::{Result, TaskList, TaskListDelta};
use crate::gossip::PubSubManager;
use saorsa_gossip_crdt_sync::AntiEntropyManager;
use saorsa_gossip_types::PeerId;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Synchronization wrapper for a TaskList.
///
/// Manages automatic background synchronization of a TaskList using
/// anti-entropy gossip. Changes are propagated via deltas published
/// to a gossip topic.
pub struct TaskListSync {
    /// The task list being synchronized (wrapped for concurrent access).
    task_list: Arc<RwLock<TaskList>>,

    /// Anti-entropy manager for periodic sync.
    #[allow(dead_code)]
    anti_entropy: AntiEntropyManager<TaskList>,

    /// Pub/sub manager for topic-based messaging.
    pubsub: Arc<PubSubManager>,

    /// Topic name for this task list.
    topic: String,
}

impl TaskListSync {
    /// Create a new TaskList synchronization manager.
    ///
    /// # Arguments
    ///
    /// * `task_list` - The TaskList to synchronize
    /// * `pubsub` - Pub/sub manager for gossip messaging
    /// * `topic` - Topic name for pub/sub (typically task list ID)
    /// * `sync_interval_secs` - How often to run anti-entropy (seconds)
    ///
    /// # Returns
    ///
    /// A new TaskListSync instance ready to start.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let task_list = TaskList::new(id, "My List".to_string(), peer_id);
    /// let sync = TaskListSync::new(
    ///     task_list,
    ///     pubsub,
    ///     "tasklist-abc123".to_string(),
    ///     30, // Sync every 30 seconds
    /// )?;
    /// ```
    pub fn new(
        task_list: TaskList,
        pubsub: Arc<PubSubManager>,
        topic: String,
        sync_interval_secs: u64,
    ) -> Result<Self> {
        // Wrap task list for concurrent access
        let task_list = Arc::new(RwLock::new(task_list));

        // Create anti-entropy manager
        let anti_entropy = AntiEntropyManager::new(Arc::clone(&task_list), sync_interval_secs);

        Ok(Self {
            task_list,
            anti_entropy,
            pubsub,
            topic,
        })
    }

    /// Start background synchronization.
    ///
    /// Subscribes to the gossip topic and begins receiving remote deltas.
    /// This method returns immediately; synchronization runs in the background.
    ///
    /// # Returns
    ///
    /// Ok(()) if started successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if subscription or anti-entropy startup fails.
    pub async fn start(&self) -> Result<()> {
        // Subscribe to topic — received messages will contain serialized deltas.
        // The background task applies them via apply_remote_delta.
        let mut sub = self.pubsub.subscribe(self.topic.clone()).await;
        let task_list = Arc::clone(&self.task_list);

        tokio::spawn(async move {
            while let Some(msg) = sub.recv().await {
                match bincode::deserialize::<(PeerId, TaskListDelta)>(&msg.payload) {
                    Ok((peer_id, delta)) => {
                        let mut list = task_list.write().await;
                        if let Err(e) = list.merge_delta(&delta, peer_id) {
                            tracing::warn!("Failed to merge remote delta: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to deserialize delta from topic: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop background synchronization.
    ///
    /// Unsubscribes from the gossip topic.
    ///
    /// # Returns
    ///
    /// Ok(()) if stopped successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if operations fail.
    pub async fn stop(&self) -> Result<()> {
        self.pubsub.unsubscribe(&self.topic).await;
        Ok(())
    }

    /// Apply a delta received from a remote peer.
    ///
    /// This is called when a delta is received via the gossip topic.
    /// The delta is merged into the local TaskList using CRDT semantics.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer who sent this delta
    /// * `delta` - The delta to apply
    ///
    /// # Returns
    ///
    /// Ok(()) if the delta was applied successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if the merge fails.
    pub async fn apply_remote_delta(&self, peer_id: PeerId, delta: TaskListDelta) -> Result<()> {
        let mut task_list = self.task_list.write().await;
        task_list.merge_delta(&delta, peer_id)?;
        Ok(())
    }

    /// Publish a local delta to the gossip network.
    ///
    /// Call this after making local changes to propagate them to other peers.
    ///
    /// # Arguments
    ///
    /// * `local_peer_id` - The local peer's ID
    /// * `delta` - The delta to publish
    ///
    /// # Returns
    ///
    /// Ok(()) if published successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or publishing fails.
    pub async fn publish_delta(
        &self,
        local_peer_id: PeerId,
        delta: TaskListDelta,
    ) -> Result<()> {
        let serialized = bincode::serialize(&(local_peer_id, delta)).map_err(|e| {
            crate::crdt::CrdtError::Gossip(format!("failed to serialize delta: {e}"))
        })?;

        self.pubsub
            .publish(self.topic.clone(), bytes::Bytes::from(serialized))
            .await
            .map_err(|e| {
                crate::crdt::CrdtError::Gossip(format!("failed to publish delta: {e}"))
            })?;

        Ok(())
    }

    /// Get a read-only reference to the task list.
    ///
    /// Useful for querying the current state without modifying it.
    ///
    /// # Returns
    ///
    /// A read guard to the TaskList.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, TaskList> {
        self.task_list.read().await
    }

    /// Get a mutable reference to the task list.
    ///
    /// Use this to make local changes. After modifying, call `publish_delta`
    /// to propagate changes to peers.
    ///
    /// # Returns
    ///
    /// A write guard to the TaskList.
    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, TaskList> {
        self.task_list.write().await
    }

    /// Get the topic name for this task list.
    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::{TaskId, TaskItem, TaskListId, TaskMetadata};
    use crate::identity::AgentId;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    fn peer(n: u8) -> PeerId {
        PeerId::new([n; 32])
    }

    fn list_id(n: u8) -> TaskListId {
        TaskListId::new([n; 32])
    }

    fn make_task(id_byte: u8, peer: PeerId) -> TaskItem {
        let agent = agent(1);
        let task_id = TaskId::from_bytes([id_byte; 32]);
        let metadata = TaskMetadata::new(
            format!("Task {}", id_byte),
            format!("Description {}", id_byte),
            128,
            agent,
            1000,
        );
        TaskItem::new(task_id, metadata, peer)
    }

    #[tokio::test]
    async fn test_task_list_sync_creation() {
        let peer = peer(1);
        let id = list_id(1);
        let task_list = TaskList::new(id, "Test List".to_string(), peer);

        // We cannot create a real PubSubManager in a unit test without a NetworkNode
        // For now, we just verify the types are correct
        let _list_for_sync = task_list;
    }

    #[tokio::test]
    async fn test_apply_delta() {
        // Create a task list
        let peer1 = peer(1);
        let peer2 = peer(2);
        let id = list_id(1);
        let task_list = TaskList::new(id, "Test".to_string(), peer1);

        // Wrap in Arc<RwLock<>>
        let task_list_arc = Arc::new(RwLock::new(task_list));

        // Create a delta with a new task
        let mut delta = TaskListDelta::new(1);
        let task = make_task(1, peer2);
        let task_id = *task.id();
        let tag = (peer2, 1);
        delta.added_tasks.insert(task_id, (task, tag));

        // Apply delta directly (simulating what TaskListSync::apply_remote_delta does)
        {
            let mut list = task_list_arc.write().await;
            let result = list.merge_delta(&delta, peer2);
            assert!(result.is_ok());
        }

        // Verify task was added
        {
            let list = task_list_arc.read().await;
            assert_eq!(list.task_count(), 1);
        }
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        // Test that RwLock allows multiple readers
        let peer = peer(1);
        let id = list_id(1);
        let task_list = TaskList::new(id, "Test".to_string(), peer);
        let task_list_arc = Arc::new(RwLock::new(task_list));

        // Multiple concurrent reads should work
        let list1 = task_list_arc.read().await;
        let list2 = task_list_arc.read().await;

        assert_eq!(list1.name(), "Test");
        assert_eq!(list2.name(), "Test");

        drop(list1);
        drop(list2);

        // Write should work after readers drop
        {
            let mut list = task_list_arc.write().await;
            list.update_name("Updated".to_string(), peer);
        }

        // Verify update
        let list = task_list_arc.read().await;
        assert_eq!(list.name(), "Updated");
    }
}
