//! #1366: the named-group listeners follow the desired state of the stored
//! group record, not only the events that start them.
//!
//! Two listeners belong to a stored group:
//! - the metadata listener, keyed by the local map key. It runs while the
//!   record is stored and not withdrawn ([`metadata_listener_wanted`]).
//! - the public-message listener, keyed by the stable id. It runs while any
//!   stored record with that stable id is not withdrawn and not
//!   `MlsEncrypted` ([`public_message_listener_wanted`]).
//!
//! Before #1366 the start paths followed this rule, but some exit paths did
//! not. A self-leave (both planes), a local-only drop, a remote
//! self-removal, a refused join stub and a cleared stale join row took the
//! record away and left the public-message listener running;
//! the TreeKEM self-leave and the cleared join row left the metadata
//! listener too. A refreshed card
//! that changed a stub to `MlsEncrypted`, and a withdrawn card, left it
//! running as well. The functions here stop a listener when no stored
//! record needs it.
//!
//! Lock order: a registry lock (`group_metadata_tasks` or
//! `public_message_tasks`), then `named_groups`, as in the install paths.
//! The callers hold no `named_groups` lock, no registry lock and no card
//! cache. Some hold the per-group membership mutex, which these functions
//! never take.

use super::*;

/// Test hook: no listener step may run while its caller holds
/// `group_card_cache`. Another path holds `named_groups` while it waits for
/// that cache, so the other order could deadlock. The record is per state,
/// so tests that share a process do not see each other's steps.
#[cfg(test)]
pub(super) fn note_listener_step(state: &AppState) {
    let recorders = &state.named_group_test_recorders;
    recorders
        .listener_steps
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if state.group_card_cache.try_write().is_err() {
        recorders
            .listener_step_held_card_cache
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Stop the public-message listener of `group_id` when no stored record
/// needs it. `group_id` is a local map key or a stable id. The desired
/// state is read under the registry write lock, so a concurrent install
/// for a record that needs the listener is kept.
pub(super) async fn retire_unwanted_public_message_listener(state: &AppState, group_id: &str) {
    #[cfg(test)]
    note_listener_step(state);
    // Cheap check first: most callers run after an apply that changed no
    // listener input, so the registry write lock is not needed.
    if public_message_listener_wanted(&*state.named_groups.read().await, group_id)
        .is_some_and(|(_, wanted)| wanted)
    {
        return;
    }
    let mut tasks = state.public_message_tasks.write().await;
    let key = match public_message_listener_wanted(&*state.named_groups.read().await, group_id) {
        Some((_, true)) => return,
        Some((stable_id, false)) => stable_id,
        None => group_id.to_string(),
    };
    if let Some(handle) = tasks.remove(&key) {
        handle.abort();
    }
}

/// Stop the metadata listener under `group_key` when the record under that
/// key is gone or withdrawn. The check and the removal run under the
/// registry write lock, so an install for a record stored again since is
/// kept.
///
/// Unlike its public twin this needs no stable-id fallback: the metadata
/// registry is keyed by the local map key only.
/// [`ensure_named_group_metadata_listener`] installs under the key it is
/// given and only for a record stored under exactly that key, so the
/// wanted rule is per key.
pub(super) async fn retire_unwanted_metadata_listener(state: &AppState, group_key: &str) {
    #[cfg(test)]
    note_listener_step(state);
    // Cheap check first: most accepted applies keep the record.
    if state
        .named_groups
        .read()
        .await
        .get(group_key)
        .is_some_and(metadata_listener_wanted)
    {
        return;
    }
    let mut tasks = state.group_metadata_tasks.write().await;
    let wanted = state
        .named_groups
        .read()
        .await
        .get(group_key)
        .is_some_and(metadata_listener_wanted);
    if wanted {
        return;
    }
    // An apply that runs on the listener's own task must not abort it: the
    // abort would cut the rest of that apply at its next await. That
    // listener ends itself when its apply reports `should_exit` and the
    // record is gone or withdrawn.
    if tasks
        .get(group_key)
        .is_some_and(|reg| tokio::task::try_id() == Some(reg.handle.id()))
    {
        return;
    }
    if let Some(reg) = tasks.remove(group_key) {
        reg.handle.abort();
    }
}

/// Stop the listeners that no stored record needs after an accepted
/// metadata event of `group_id` (a stable id or local key). `local_keys`
/// are the local keys of that group read before the apply, which can
/// remove the record. Every path that applies a metadata event calls this
/// through [`apply_named_group_metadata_event`]: the topic listener, the
/// direct lanes, catch-up, the parked-event replays and the recovery
/// replays. Starts stay with the paths that seat a record.
///
/// The caller holds no group lock: the apply has released its membership,
/// persistence and map locks when it returns.
pub(super) async fn retire_listeners_after_accepted_apply(
    state: &AppState,
    group_id: &str,
    local_keys: &[String],
) {
    retire_unwanted_public_message_listener(state, group_id).await;
    for key in local_keys {
        retire_unwanted_metadata_listener(state, key).await;
    }
}

/// Stop both listeners of a record the caller has just removed from
/// `named_groups`, when no stored record needs them. `group_key` is the
/// removed local map key; `stable_id` is the stable id it carried.
pub(super) async fn retire_listeners_of_removed_record(
    state: &AppState,
    group_key: &str,
    stable_id: Option<&str>,
) {
    retire_unwanted_metadata_listener(state, group_key).await;
    retire_unwanted_public_message_listener(state, group_key).await;
    if let Some(stable_id) = stable_id.filter(|stable_id| *stable_id != group_key) {
        retire_unwanted_public_message_listener(state, stable_id).await;
    }
}

/// Make both listeners of a group match its stored record: start each
/// listener the record needs and stop each one it does not need. `group_key`
/// is the local map key. `stable_id` is the stable id of the record, which
/// the caller reads before a removal: after the removal the key alone cannot
/// name the public-message listener.
pub(super) async fn reconcile_named_group_listeners(
    state: &Arc<AppState>,
    group_key: &str,
    stable_id: Option<&str>,
) {
    retire_unwanted_metadata_listener(state, group_key).await;
    ensure_named_group_metadata_listener(Arc::clone(state), group_key).await;
    reconcile_public_message_listener(state, group_key).await;
    if let Some(stable_id) = stable_id.filter(|stable_id| *stable_id != group_key) {
        reconcile_public_message_listener(state, stable_id).await;
    }
}
