//! Route-handler modules for the x0x daemon, grouped by the `category`
//! field of the shared endpoint registry (`src/api/mod.rs`).
//!
//! Part of the `server/mod.rs` decomposition (#125 / WS1.4). Each submodule
//! holds the verbatim handler bodies and request/response DTOs for one
//! registry category; the router wiring stays in the parent module.

mod contacts;
mod files;
mod identity;
mod machines;
mod status;
mod tasks;
mod upgrade;

#[cfg(test)]
pub(super) use contacts::UpdateContactRequest;
pub(super) use contacts::{
    add_contact, delete_contact, list_contacts, list_revocations, quick_trust, revoke_contact,
    update_contact,
};
pub(super) use files::{
    FileChunkAckSlot, file_accept_handler, file_reject_handler, file_send_handler,
    file_transfer_send_config, file_transfer_status_handler, file_transfers_handler,
    handle_file_message, wait_for_chunk_window, wait_for_final_acks,
};
pub(super) use identity::{
    agent_info, agent_sign, agent_user_id_handler, agent_verify, announce_identity,
    get_a2a_agent_card, get_agent_card, identity_revocations, identity_revoke, import_agent_card,
    introduction, populate_invite_base_state_from_group_info,
};
#[cfg(test)]
pub(super) use identity::{CardQuery, ImportCardRequest};
pub(super) use status::{get_constitution, get_constitution_json, health, shutdown_handler, status};
pub(super) use machines::{
    add_machine, delete_machine, discovered_machine, discovered_machines, list_machines,
    machines_by_user_handler, pin_machine, unpin_machine,
};
pub(super) use upgrade::{
    SelfPublishedReleaseManifests, apply_upgrade, broadcast_current_manifest, check_upgrade,
    run_fallback_github_poll, run_gossip_update_listener, run_startup_update_check,
};
pub(super) use tasks::{
    add_task, apply_group_authorization, create_task_list, list_task_lists, list_tasks, update_task,
};
