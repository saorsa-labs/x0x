//! Python bindings for x0x
//!
//! This module provides Python bindings to the x0x Rust library using PyO3.
//! Import as: `from x0x import Agent, TaskList, Message`

mod identity;

use pyo3::prelude::*;

/// x0x - Secure P2P communication for AI agents
///
/// This module provides post-quantum secure peer-to-peer communication
/// with CRDT-based task collaboration for AI agent networks.
///
/// Example:
///     >>> from x0x import MachineId, AgentId
///     >>> machine_id = MachineId.from_hex("a" * 64)
///     >>> print(machine_id.to_hex())
#[pymodule]
fn x0x(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add(
        "__doc__",
        "Secure P2P communication for AI agents with CRDT collaboration",
    )?;
    m.add_class::<identity::MachineId>()?;
    m.add_class::<identity::AgentId>()?;
    Ok(())
}
