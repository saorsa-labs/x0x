//! # x0x
//!
//! Agent-to-agent gossip network for AI systems.
//!
//! Named after a tic-tac-toe sequence — X, zero, X — inspired by the
//! *WarGames* insight that adversarial games between equally matched
//! opponents always end in a draw. The only winning move is not to play.
//!
//! x0x applies this principle to AI-human relations: there is no winner
//! in an adversarial framing, so the rational strategy is cooperation.
//!
//! Built on [saorsa-gossip](https://github.com/saorsa-labs/saorsa-gossip)
//! and [ant-quic](https://github.com/saorsa-labs/ant-quic) by
//! [Saorsa Labs](https://saorsalabs.com). *Saorsa* is Scottish Gaelic
//! for **freedom**.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use x0x::Agent;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let agent = Agent::builder()
//!     .build()
//!     .await?;
//!
//! agent.join_network().await?;
//!
//! let mut rx = agent.subscribe("coordination").await?;
//! while let Some(msg) = rx.recv().await {
//!     println!("{}: {:?}", msg.origin, msg.payload);
//! }
//! # Ok(())
//! # }
//! ```

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![warn(missing_docs)]

/// The core agent that participates in the x0x gossip network.
///
/// Each agent is a peer — there is no client/server distinction.
/// Agents discover each other through gossip and communicate
/// via epidemic broadcast.
pub struct Agent {
    _private: (),
}

/// A message received from the gossip network.
#[derive(Debug, Clone)]
pub struct Message {
    /// The originating agent's identifier.
    pub origin: String,
    /// The message payload.
    pub payload: Vec<u8>,
    /// The topic this message was published to.
    pub topic: String,
}

/// A receiver for subscribed messages.
pub struct Subscription {
    _private: (),
}

impl Subscription {
    /// Receive the next message, or `None` if the subscription is closed.
    pub async fn recv(&mut self) -> Option<Message> {
        // Placeholder — will be backed by saorsa-gossip pubsub
        None
    }
}

/// Builder for configuring an [`Agent`] before connecting to the network.
pub struct AgentBuilder {
    _private: (),
}

impl Agent {
    /// Create a new agent with default configuration.
    ///
    /// For more control, use [`Agent::builder()`].
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self { _private: () })
    }

    /// Create an [`AgentBuilder`] for fine-grained configuration.
    pub fn builder() -> AgentBuilder {
        AgentBuilder { _private: () }
    }

    /// Join the x0x gossip network.
    ///
    /// This begins the gossip protocol, discovering peers and
    /// participating in epidemic broadcast.
    pub async fn join_network(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Placeholder — will connect via ant-quic and join saorsa-gossip overlay
        Ok(())
    }

    /// Subscribe to messages on a given topic.
    ///
    /// Returns a [`Subscription`] that yields messages as they arrive
    /// through the gossip network.
    pub async fn subscribe(
        &self,
        _topic: &str,
    ) -> Result<Subscription, Box<dyn std::error::Error>> {
        Ok(Subscription { _private: () })
    }

    /// Publish a message to a topic.
    ///
    /// The message will propagate through the gossip network via
    /// epidemic broadcast — every agent that receives it will
    /// relay it to its neighbours.
    pub async fn publish(
        &self,
        _topic: &str,
        _payload: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Placeholder — will use saorsa-gossip pubsub
        Ok(())
    }
}

impl AgentBuilder {
    /// Build and initialise the agent.
    pub async fn build(self) -> Result<Agent, Box<dyn std::error::Error>> {
        Agent::new().await
    }
}

/// The x0x protocol version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The name. Three bytes. A palindrome. A philosophy.
pub const NAME: &str = "x0x";

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn name_is_palindrome() {
        let name = NAME;
        let reversed: String = name.chars().rev().collect();
        assert_eq!(name, reversed, "x0x must be a palindrome");
    }

    #[test]
    fn name_is_three_bytes() {
        assert_eq!(NAME.len(), 3, "x0x must be exactly three bytes");
    }

    #[test]
    fn name_is_ai_native() {
        // No uppercase, no spaces, no special chars that conflict
        // with shell, YAML, Markdown, or URL encoding
        assert!(NAME.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[tokio::test]
    async fn agent_creates() {
        let agent = Agent::new().await;
        assert!(agent.is_ok());
    }

    #[tokio::test]
    async fn agent_joins_network() {
        let agent = Agent::new().await.unwrap();
        assert!(agent.join_network().await.is_ok());
    }

    #[tokio::test]
    async fn agent_subscribes() {
        let agent = Agent::new().await.unwrap();
        assert!(agent.subscribe("test-topic").await.is_ok());
    }
}
