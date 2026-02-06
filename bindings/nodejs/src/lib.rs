#![deny(clippy::all)]

mod agent;
mod events;
mod identity;

pub use agent::{Agent, AgentBuilder, Message, Subscription};
pub use events::{
    ErrorEvent, EventListener, MessageEvent, PeerConnectedEvent, PeerDisconnectedEvent,
    TaskUpdatedEvent,
};
pub use identity::{AgentId, MachineId};
