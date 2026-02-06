//! Pub/Sub message types for Python bindings.

use pyo3::prelude::*;

use crate::identity::AgentId;

/// A message received from the gossip network.
///
/// Messages are published to topics and delivered to all subscribers
/// of that topic through epidemic broadcast.
///
/// # Example (Python)
///
/// ```python
/// async for msg in agent.subscribe("announcements"):
///     print(f"From {msg.sender}: {msg.payload.decode()}")
///     print(f"Timestamp: {msg.timestamp}")
/// ```
#[pyclass]
#[derive(Clone)]
pub struct Message {
    /// The message payload as bytes.
    #[pyo3(get)]
    pub payload: Vec<u8>,

    /// The agent ID of the sender.
    #[pyo3(get)]
    pub sender: AgentId,

    /// Unix timestamp (seconds since epoch) when message was created.
    #[pyo3(get)]
    pub timestamp: i64,
}

#[pymethods]
impl Message {
    /// String representation showing sender and payload length.
    fn __repr__(&self) -> String {
        // Access sender's inner bytes directly for hex encoding
        format!(
            "Message(sender=<AgentId>, payload_len={}, timestamp={})",
            self.payload.len(),
            self.timestamp
        )
    }

    /// String representation for debugging.
    fn __str__(&self) -> String {
        self.__repr__()
    }
}

impl Message {
    /// Create a new message.
    pub fn new(payload: Vec<u8>, sender: AgentId, timestamp: i64) -> Self {
        Self {
            payload,
            sender,
            timestamp,
        }
    }
}

/// Async iterator for receiving messages from a subscription.
///
/// This implements the Python async iterator protocol (__aiter__ and __anext__)
/// to allow usage with `async for` loops.
///
/// # Example (Python)
///
/// ```python
/// subscription = agent.subscribe("my-topic")
/// async for msg in subscription:
///     process(msg)
/// ```
#[pyclass]
pub struct Subscription {
    topic: String,
    #[pyo3(get)]
    closed: bool,
}

#[pymethods]
impl Subscription {
    /// Make this object an async iterator (returns self).
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Get the next message from the subscription.
    ///
    /// Returns None (StopAsyncIteration in Python) when subscription is closed.
    /// This is a placeholder - actual implementation will use saorsa-gossip when available.
    fn __anext__(&mut self) -> Option<Message> {
        // Placeholder: Always returns None to signal end of iteration
        // When gossip integration is complete, this will:
        // 1. Await the next message from the gossip pubsub channel
        // 2. Return Some(Message) when available
        // 3. Return None when subscription closed/no more messages
        // 4. Handle cancellation/unsubscribe properly
        None
    }

    /// Close the subscription and stop receiving messages.
    ///
    /// After calling close(), the iterator will stop yielding messages.
    fn close(&mut self) {
        self.closed = true;
    }

    /// Get the topic this subscription is listening to.
    #[getter]
    fn topic(&self) -> &str {
        &self.topic
    }
}

impl Subscription {
    /// Create a new subscription for a topic.
    pub fn new(topic: String) -> Self {
        Self {
            topic,
            closed: false,
        }
    }
}
