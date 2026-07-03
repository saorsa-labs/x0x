//! Route-handler modules for the x0x daemon, grouped by the `category`
//! field of the shared endpoint registry (`src/api/mod.rs`).
//!
//! Part of the `server/mod.rs` decomposition (#125 / WS1.4). Each submodule
//! holds the verbatim handler bodies and request/response DTOs for one
//! registry category; the router wiring stays in the parent module.

mod contacts;
mod identity;
mod machines;

pub(super) use contacts::{
    add_contact, delete_contact, list_contacts, list_revocations, quick_trust, revoke_contact,
    update_contact,
};
#[cfg(test)]
pub(super) use identity::CardQuery;
pub(super) use identity::{
    agent_info, agent_sign, agent_user_id_handler, agent_verify, announce_identity,
    get_a2a_agent_card, get_agent_card, import_agent_card, introduction,
    populate_invite_base_state_from_group_info,
};
pub(super) use machines::{
    add_machine, delete_machine, discovered_machine, discovered_machines, list_machines,
    machines_by_user_handler, pin_machine, unpin_machine,
};
