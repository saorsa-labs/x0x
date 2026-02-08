//! Python bindings for x0x
//!
//! This module provides Python bindings to the x0x Rust library using PyO3.
//! Import as: `from x0x import Agent, TaskList, Message`

#![allow(non_local_definitions)] // False positive with pyo3 0.20 macros

mod agent;
mod config;
mod events;
mod health;
mod identity;
mod pubsub;
mod task_list;

use pyo3::prelude::*;

/// x0x - Secure P2P communication for AI agents
///
/// This module provides post-quantum secure peer-to-peer communication
/// with CRDT-based task collaboration for AI agent networks.
///
/// Example:
///     >>> from x0x import Agent, TaskList, MachineId, AgentId
///     >>> machine_id = MachineId.from_hex("a" * 64)
///     >>> print(machine_id.to_hex())
#[pymodule]
fn x0x(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add(
        "__doc__",
        "Secure P2P communication for AI agents with CRDT collaboration",
    )?;
    m.add_class::<identity::MachineId>()?;
    m.add_class::<identity::AgentId>()?;
    m.add_class::<agent::Agent>()?;
    m.add_class::<agent::AgentBuilder>()?;
    m.add_class::<pubsub::Message>()?;
    m.add_class::<pubsub::Subscription>()?;
    m.add_class::<task_list::TaskId>()?;
    m.add_class::<task_list::TaskItem>()?;
    m.add_class::<task_list::TaskList>()?;
    Ok(())
}
