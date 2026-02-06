#![deny(clippy::all)]

mod agent;
mod identity;

pub use agent::{Agent, AgentBuilder};
pub use identity::{AgentId, MachineId};
