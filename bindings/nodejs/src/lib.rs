#![deny(clippy::all)]

mod agent;
mod events;
mod identity;
mod task_list;

pub use agent::{Agent, AgentBuilder, Message, Subscription};
pub use events::{ErrorEvent, EventListener, PeerConnectedEvent, PeerDisconnectedEvent};
pub use identity::{AgentId, MachineId};
pub use task_list::{TaskList, TaskSnapshot};
