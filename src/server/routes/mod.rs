//! Route-handler modules for the x0x daemon, grouped by the `category`
//! field of the shared endpoint registry (`src/api/mod.rs`).
//!
//! Part of the `server/mod.rs` decomposition (#125 / WS1.4). Each submodule
//! holds the verbatim handler bodies and request/response DTOs for one
//! registry category; the router wiring stays in the parent module.

mod connect;
mod contacts;
mod direct;
mod discovery;
mod exec;
mod files;
mod groups;
mod history;
mod identity;
mod machines;
mod messaging;
mod named_groups;
mod network;
mod presence;
mod status;
mod stores;
mod tasks;
mod trust;
mod upgrade;

pub(super) use connect::{
    connect_diagnostics_handler, forward_add, forward_list, forward_remove, streams_diagnostics,
};
pub(super) use contacts::{
    add_contact, delete_contact, list_contacts, list_revocations, quick_trust, revoke_contact,
    update_contact,
};
pub(super) use direct::{
    connect_agent, connect_machine, direct_connections, direct_message_send_config, direct_send,
};
pub(super) use discovery::{
    agent_reachability, agents_by_user_handler, discovered_agent, discovered_agent_entry,
    discovered_agents, find_agent, machine_for_agent_handler, DiscoveredAgentEntry,
};
pub(super) use exec::{exec_cancel, exec_diagnostics, exec_run, exec_sessions};
pub(super) use files::{
    file_accept_handler, file_reject_handler, file_send_handler, file_transfer_status_handler,
    file_transfers_handler, handle_file_message, FileChunkAckSlot,
};
pub(super) use groups::{
    add_mls_member, create_mls_group, create_mls_welcome, get_mls_group, list_mls_groups,
    mls_decrypt, mls_encrypt, remove_mls_member,
};
pub(super) use history::{
    history_diagnostics, history_list, history_purge, history_search, history_stats,
};
pub(super) use identity::{
    agent_info, agent_sign, agent_user_id_handler, agent_verify, announce_identity,
    get_a2a_agent_card, get_agent_card, identity_revocations, identity_revoke, import_agent_card,
    introduction,
};
pub(super) use machines::{
    add_machine, delete_machine, discovered_machine, discovered_machines, list_machines,
    machines_by_user_handler, pin_machine, unpin_machine,
};
pub(super) use messaging::{publish, subscribe, unsubscribe, RestSubscription};
pub(super) use named_groups::{
    add_named_group_member, apply_named_group_metadata_event, approve_join_request,
    ban_group_member, cancel_join_request, create_discovery_subscription, create_group_invite,
    create_join_request, create_named_group, delete_discovery_subscription, discover_groups,
    discover_groups_nearby, ensure_named_group_listeners, get_group_card,
    get_group_public_messages, get_group_state, get_group_state_commits, get_named_group,
    get_named_group_members, handle_join_result_message, handle_treekem_catchup_request,
    handle_treekem_catchup_response, handle_welcome_blob_message, import_group_card,
    ingest_public_message, join_group_via_invite, leave_group, list_discovery_subscriptions,
    list_join_requests, list_named_groups, load_named_groups, load_treekem_member_key_packages,
    named_group_metadata_event_kind, publish_group_card_to_discovery,
    recover_treekem_named_journals, reject_join_request, remove_named_group_member,
    restore_treekem_groups, seal_group_state, secure_group_decrypt, secure_group_encrypt,
    secure_group_reseal, secure_open_envelope_adversarial, send_group_public_message,
    set_group_display_name, spawn_directory_resubscribe, spawn_global_discovery_listener,
    spawn_global_public_message_listener, spawn_listed_to_contacts_listener, unban_group_member,
    update_group_policy, update_member_role, update_named_group, withdraw_group_state,
    ExpectedJoinResultInviter, JoinResultMessage, NamedGroupMetadataEvent, PendingJoinResult,
    PendingTreeKemMetadataEvent, PendingWelcome, PendingWelcomeReceive, TreeKemCatchupRequest,
    TreeKemCatchupResponse, TreeKemMemberKeyPackageCache, WelcomeBlobMessage, WelcomeFetchWaiter,
    DIRECTORY_DIGEST_INTERVAL_SECS, DIRECTORY_RESUBSCRIBE_JITTER_MS,
    GROUP_PUBLIC_MESSAGE_DM_PREFIX,
};
pub(super) use network::{
    ack_diagnostics, bootstrap_cache_stats, connectivity_diagnostics, dm_diagnostics,
    gossip_diagnostics, groups_diagnostics, network_status, peer_health_handler, peers,
    probe_peer_handler,
};
pub(super) use presence::{
    presence, presence_find, presence_foaf, presence_online, presence_status,
};
pub(super) use status::{
    get_constitution, get_constitution_json, health, shutdown_handler, status,
};
pub(super) use stores::{
    apply_direct_kv_store_delta, create_kv_store, delete_kv_value, get_kv_value, join_kv_store,
    list_kv_keys, list_kv_stores, put_kv_value, KvStoreDirectDelta, KV_STORE_DELTA_DM_PREFIX,
};
pub(super) use tasks::{
    add_task, apply_group_authorization, create_task_list, list_task_lists, list_tasks, update_task,
};
pub(super) use trust::evaluate_trust;
pub(super) use upgrade::{
    apply_upgrade, broadcast_current_manifest, check_upgrade, run_fallback_github_poll,
    run_gossip_update_listener, run_startup_update_check, SelfPublishedReleaseManifests,
};
