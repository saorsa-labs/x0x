//! Task list synchronization using gossip pub/sub.
//!
//! This module provides automatic synchronization of TaskLists across peers
//! using saorsa-gossip's pub/sub delta propagation.
//!
//! ## Architecture
//!
//! - `TaskListSync` wraps a TaskList in Arc<RwLock<>> for concurrent access
//! - Publishes deltas to a gossip topic when local changes occur
//! - Subscribes to the topic to receive and apply remote deltas
//! - Runs a `StateRequest` cold-start side channel so a first-time joiner
//!   bootstraps tasks written before it subscribed (mirrors `KvStoreSync`)
//!
//! This provides eventual consistency across all peers sharing the same topic.

use crate::crdt::{Result, TaskList, TaskListDelta};
use crate::gossip::wire::{decode_delta, encode_delta};
use crate::gossip::PubSubManager;
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Suffix appended to a task-list topic to form its state-sync side channel.
///
/// State requests travel on a separate topic so the main topic keeps its
/// existing `(PeerId, TaskListDelta)` wire format — peers that predate this
/// channel simply never subscribe to it and are unaffected.
const STATE_SYNC_TOPIC_SUFFIX: &str = "/state-sync";

/// Delays between state-request retries for a first-time joiner whose task
/// list is still empty. Spread out so a slow mesh still converges without
/// flooding.
const STATE_REQUEST_RETRY_SECS: [u64; 4] = [1, 5, 15, 30];

/// Message exchanged on the state-sync side topic.
#[derive(Debug, Serialize, Deserialize)]
enum TaskListSyncMessage {
    /// A peer with no local state for the list asks holders to republish
    /// their full state (as a regular delta) on the main topic.
    StateRequest { requester: PeerId },
}

/// Synchronization wrapper for a TaskList.
///
/// Manages automatic background synchronization of a TaskList using gossip
/// pub/sub. Changes are propagated via deltas published to a gossip topic.
pub struct TaskListSync {
    /// The task list being synchronized (wrapped for concurrent access).
    task_list: Arc<RwLock<TaskList>>,

    /// Pub/sub manager for topic-based messaging.
    pubsub: Arc<PubSubManager>,

    /// Topic name for this task list.
    topic: String,

    /// This node's gossip peer id — identifies our deltas and state
    /// requests on the wire.
    local_peer_id: PeerId,
}

impl TaskListSync {
    /// Create a new TaskList synchronization manager.
    ///
    /// # Arguments
    ///
    /// * `task_list` - The TaskList to synchronize
    /// * `pubsub` - Pub/sub manager for gossip messaging
    /// * `topic` - Topic name for pub/sub (typically task list ID)
    /// * `local_peer_id` - This node's gossip peer id
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
    ///     peer_id,
    /// )?;
    /// ```
    pub fn new(
        task_list: TaskList,
        pubsub: Arc<PubSubManager>,
        topic: String,
        local_peer_id: PeerId,
    ) -> Result<Self> {
        // Wrap task list for concurrent access
        let task_list = Arc::new(RwLock::new(task_list));

        Ok(Self {
            task_list,
            pubsub,
            topic,
            local_peer_id,
        })
    }

    /// The state-sync side topic for this task list.
    fn state_sync_topic(&self) -> String {
        format!("{}{}", self.topic, STATE_SYNC_TOPIC_SUFFIX)
    }

    /// Start background synchronization.
    ///
    /// Subscribes to the gossip topic and begins receiving remote deltas.
    /// Also joins the state-sync side channel: holders answer state requests
    /// by republishing their full state, and a first-time joiner (empty local
    /// list) requests that state so it bootstraps tasks written before it
    /// subscribed. Without this, only deltas published *after* subscribing
    /// ever arrive. This method returns immediately; synchronization runs in
    /// the background.
    ///
    /// # Returns
    ///
    /// Ok(()) if started successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if subscription startup fails.
    pub async fn start(&self) -> Result<()> {
        // Subscribe to topic — received messages will contain serialized deltas.
        let mut sub = self.pubsub.subscribe(self.topic.clone()).await;
        let task_list = Arc::clone(&self.task_list);

        tokio::spawn(async move {
            while let Some(msg) = sub.recv().await {
                match decode_delta::<TaskListDelta>(&msg.payload) {
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

        // Responder: holders with non-empty state answer StateRequests by
        // republishing their full state as a regular delta on the main topic.
        // CRDT merge makes duplicate responses from multiple holders harmless
        // (idempotent), so no response suppression is needed at current mesh
        // sizes.
        let mut sync_sub = self.pubsub.subscribe(self.state_sync_topic()).await;
        let responder_list = Arc::clone(&self.task_list);
        let responder_pubsub = Arc::clone(&self.pubsub);
        let responder_topic = self.topic.clone();
        let local_peer_id = self.local_peer_id;
        tokio::spawn(async move {
            while let Some(msg) = sync_sub.recv().await {
                let Ok(TaskListSyncMessage::StateRequest { requester }) =
                    bincode::deserialize::<TaskListSyncMessage>(&msg.payload)
                else {
                    continue;
                };
                if requester == local_peer_id {
                    continue;
                }
                let full = {
                    let list = responder_list.read().await;
                    if list.task_count() == 0 {
                        continue;
                    }
                    list.full_delta()
                };
                let Ok(serialized) = encode_delta(local_peer_id, &full) else {
                    continue;
                };
                if let Err(e) = responder_pubsub
                    .publish(responder_topic.clone(), bytes::Bytes::from(serialized))
                    .await
                {
                    tracing::warn!("TaskList state-response publish failed: {e}");
                }
            }
        });

        // Bootstrap requester: a first-time joiner starts with an empty list
        // and has no other way to learn tasks written before it subscribed
        // (the gossip message cache only replays recent deltas). Ask holders
        // to republish over a short retry schedule. Requests and the
        // full-delta responses they trigger are idempotent CRDT merges, so the
        // extra chatter is bounded and harmless. A creator of a genuinely new
        // list also sends these — nobody answers.
        if self.task_list.read().await.task_count() == 0 {
            let requester_pubsub = Arc::clone(&self.pubsub);
            let sync_topic = self.state_sync_topic();
            tokio::spawn(async move {
                for delay_secs in STATE_REQUEST_RETRY_SECS {
                    tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
                    let request = TaskListSyncMessage::StateRequest {
                        requester: local_peer_id,
                    };
                    let Ok(serialized) = bincode::serialize(&request) else {
                        return;
                    };
                    if let Err(e) = requester_pubsub
                        .publish(sync_topic.clone(), bytes::Bytes::from(serialized))
                        .await
                    {
                        tracing::debug!("TaskList state-request publish failed: {e}");
                    }
                }
            });
        }

        Ok(())
    }

    /// Stop background synchronization.
    ///
    /// Unsubscribes from the gossip topic and its state-sync side channel.
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
        self.pubsub.unsubscribe(&self.state_sync_topic()).await;
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
    pub async fn publish_delta(&self, local_peer_id: PeerId, delta: TaskListDelta) -> Result<()> {
        let serialized = encode_delta(local_peer_id, &delta).map_err(|e| {
            crate::crdt::CrdtError::Gossip(format!("failed to serialize delta: {e}"))
        })?;

        self.pubsub
            .publish(self.topic.clone(), bytes::Bytes::from(serialized))
            .await
            .map_err(|e| crate::crdt::CrdtError::Gossip(format!("failed to publish delta: {e}")))?;

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
